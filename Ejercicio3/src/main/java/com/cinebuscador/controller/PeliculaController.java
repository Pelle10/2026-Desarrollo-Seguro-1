package com.cinebuscador.controller;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.MediaTypeFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.cinebuscador.model.Pelicula;
import com.cinebuscador.repository.PeliculaRepository;

import jakarta.persistence.EntityNotFoundException;

@Controller
public class PeliculaController {

    private final PeliculaRepository peliculaRepo;

    @Value("${app.upload-dir}")
    private String uploadDir;

    // ==================== MITIGACIÓN (CWE-434 - Unrestricted File Upload) ====================
    // 1. Whitelist de extensiones/tipos MIME permitidos: solo imágenes.
    // 2. Límite de tamaño de archivo.

    private static final Set<String> EXTENSIONES_PERMITIDAS = Set.of("png", "jpg", "jpeg", "gif", "webp");
    private static final Set<String> MIME_PERMITIDOS = Set.of(
            "image/png", "image/jpeg", "image/gif", "image/webp");
    private static final long TAMANIO_MAXIMO_BYTES = 5L * 1024 * 1024; // 5 MB

    public PeliculaController(PeliculaRepository peliculaRepo) {
        this.peliculaRepo = peliculaRepo;
    }

    @GetMapping("/")
    public String index(@RequestParam(required = false) String buscar,
                        @RequestParam(required = false, defaultValue = "nombre") String ordenarPor,
                        @RequestParam(required = false, defaultValue = "ASC") String sentido,
                        Model model) {

        if (buscar != null && !buscar.isBlank()) {
            List<Object[]> resultadosRaw;
            if ("DESC".equalsIgnoreCase(sentido)) {
                resultadosRaw = peliculaRepo.searchWithFuncionesDesc(buscar, ordenarPor);
            } else {
                resultadosRaw = peliculaRepo.searchWithFunciones(buscar, ordenarPor);
            }

            List<Map<String, Object>> resultados = new java.util.ArrayList<>();
            for (Object[] row : resultadosRaw) {
                Map<String, Object> map = new HashMap<>();
                map.put("id",        row[0]);
                map.put("nombre",    row[1]);
                map.put("fechaHora", row[2]);
                map.put("disponibles", row[3]);
                map.put("descripcion", row[4]);
                map.put("afichePath", row[5]);
                resultados.add(map);
            }
            model.addAttribute("resultados", resultados);
        }

        model.addAttribute("query", buscar != null ? buscar : "");
        model.addAttribute("sort_by", ordenarPor);
        model.addAttribute("sort_dir", sentido);
        return "index";
    }

    @GetMapping("/upload/{id}")
    public String uploadForm(@PathVariable Integer id, Model model) {
        Pelicula pelicula = peliculaRepo.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("Pelicula no encontrada"));
        model.addAttribute("pelicula", pelicula);
        return "upload";
    }

    @PostMapping("/upload/{id}")
    public String uploadFile(@PathVariable Integer id,
                             @RequestParam("afiche") MultipartFile archivo) throws IOException {
        Pelicula pelicula = peliculaRepo.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("Pelicula no encontrada"));

        if (archivo.isEmpty()) {
            throw new IllegalArgumentException("El archivo está vacío");
        }
        if (archivo.getSize() > TAMANIO_MAXIMO_BYTES) {
            throw new IllegalArgumentException("El archivo supera el tamaño máximo permitido (5MB)");
        }

        String nombreOriginal = archivo.getOriginalFilename();
        String extension = extraerExtension(nombreOriginal);
        if (!EXTENSIONES_PERMITIDAS.contains(extension)) {
            throw new IllegalArgumentException("Tipo de archivo no permitido. Solo se aceptan imágenes: "
                    + EXTENSIONES_PERMITIDAS);
        }

        // Validar el contenido real del archivo, no solo su nombre/extensión declarada.
        String tipoDetectado = detectarTipoContenido(archivo);
        if (tipoDetectado == null || !MIME_PERMITIDOS.contains(tipoDetectado)) {
            throw new IllegalArgumentException("El contenido del archivo no corresponde a una imagen válida");
        }

        String filename = UUID.randomUUID() + "." + extension;

        Path uploadPath = Paths.get(uploadDir).toAbsolutePath().normalize();
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }
        Path destino = uploadPath.resolve(filename).normalize();
        if (!destino.startsWith(uploadPath)) {
            throw new IllegalArgumentException("Nombre de archivo inválido");
        }

        try (InputStream in = archivo.getInputStream()) {
            Files.copy(in, destino);
        }

        pelicula.setAfichePath(filename);
        peliculaRepo.save(pelicula);

        return "redirect:/";
    }

    private String extraerExtension(String nombreOriginal) {
        if (nombreOriginal == null) {
            return "";
        }
        String base = Paths.get(nombreOriginal).getFileName().toString();
        int idx = base.lastIndexOf('.');
        if (idx < 0 || idx == base.length() - 1) {
            return "";
        }
        return base.substring(idx + 1).toLowerCase();
    }

    private String detectarTipoContenido(MultipartFile archivo) throws IOException {
        String declarado = archivo.getContentType();
        if (declarado != null && MIME_PERMITIDOS.contains(declarado)) {
            byte[] cabecera = new byte[12];
            try (InputStream in = archivo.getInputStream()) {
                int leidos = in.read(cabecera);
                if (leidos > 0 && esImagenPorMagicBytes(cabecera)) {
                    return declarado;
                }
            }
        }
        return null;
    }

    private boolean esImagenPorMagicBytes(byte[] b) {
        // PNG
        if (b.length >= 8 && (b[0] & 0xFF) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') {
            return true;
        }
        // JPEG
        if (b.length >= 3 && (b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF) {
            return true;
        }
        // GIF
        if (b.length >= 6 && b[0] == 'G' && b[1] == 'I' && b[2] == 'F') {
            return true;
        }
        // WEBP (RIFF....WEBP)
        if (b.length >= 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F'
                && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') {
            return true;
        }
        return false;
    }

    @GetMapping("/uploads/{filename:.+}")
    @ResponseBody
    public ResponseEntity<Resource> serveFile(@PathVariable String filename) throws IOException {
        Path uploadPath = Paths.get(uploadDir).toAbsolutePath().normalize();
        Path filePath = uploadPath.resolve(filename).normalize();

        // MITIGACIÓN (CWE-22 - Path Traversal): se verifica que el archivo
        // resuelto siga estando dentro del directorio de subidas antes de servirlo.
        if (!filePath.startsWith(uploadPath)) {
            return ResponseEntity.badRequest().build();
        }

        Resource resource = new UrlResource(filePath.toUri());
        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }

        MediaType mediaType = MediaTypeFactory.getMediaType(resource)
        .orElse(MediaType.APPLICATION_OCTET_STREAM);

        return ResponseEntity.ok()
            .contentType(mediaType)
            // Ya solo se sirven archivos que pasaron la validación de tipo/
            // contenido de imagen, por lo que "inline" es seguro aquí
            .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + resource.getFilename() + "\"")
            .body(resource);
    }

}