package com.cinebuscador.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Servicio de manejo seguro de contraseñas.
 *
 * MITIGACIÓN (CWE-312 - Cleartext Storage / CWE-916 - Uso de un algoritmo de
 * hash inadecuado para contraseñas / CWE-798 - Credenciales embebidas):
 *
 * La versión original de esta clase tenía tres problemas graves:
 *
 *   1) Usaba CIFRADO REVERSIBLE (AES) para "proteger" contraseñas. Las
 *      contraseñas nunca deben poder recuperarse en texto claro: si la base
 *      de datos o el código fuente se filtran, un cifrado reversible permite
 *      recuperar TODAS las contraseñas de TODOS los usuarios. La solución
 *      correcta es un HASH DE UNA SOLA VÍA (no reversible).
 *   2) Usaba el modo AES/ECB, que es determinístico: la misma contraseña
 *      siempre produce el mismo texto cifrado, lo que permite detectar
 *      usuarios con contraseñas repetidas y facilita ataques de diccionario
 *      precalculados (rainbow tables a nivel de bloque).
 *   3) La clave de cifrado estaba embebida como constante en el código
 *      fuente (CWE-798), visible para cualquiera con acceso al repositorio,
 *      y además existían métodos que la exponían directamente
 *      (getStaticKey/getKeyBytes/getKeyHex).
 *
 * La mitigación reemplaza el cifrado por BCrypt:
 *   - Es un algoritmo de HASH de una sola vía: no existe forma de "decrypt".
 *   - Genera una SAL ALEATORIA distinta por cada contraseña automáticamente
 *     y la incluye en el propio hash de salida, por lo que dos usuarios con
 *     la misma contraseña obtienen hashes distintos.
 *   - Es deliberadamente lento (factor de costo configurable), lo que
 *     dificulta ataques de fuerza bruta / diccionario a gran escala.
 *   - No depende de ninguna clave secreta embebida en el código: no hay
 *     nada equivalente a SECRET_KEY que proteger o que se pueda filtrar.
 */
public class EncryptionService {

    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    /**
     * Genera el hash BCrypt (con sal aleatoria incluida) de una contraseña
     * en texto plano. El resultado es lo único que se guarda en la base de
     * datos.
     */
    public static String hashPassword(String plaintext) {
        return ENCODER.encode(plaintext);
    }

    /**
     * Verifica una contraseña en texto plano contra un hash BCrypt
     * previamente almacenado. Nunca se "descifra" el hash: se recalcula y
     * se compara de forma segura (constant-time) internamente por BCrypt.
     */
    public static boolean matches(String plaintextCandidato, String hashAlmacenado) {
        if (plaintextCandidato == null || hashAlmacenado == null) {
            return false;
        }
        return ENCODER.matches(plaintextCandidato, hashAlmacenado);
    }
}
