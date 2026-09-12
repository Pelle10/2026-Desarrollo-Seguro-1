package com.cinebuscador.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.cinebuscador.config.EncryptionService;
import com.cinebuscador.model.User;
import com.cinebuscador.repository.UserRepository;

@Controller
public class AuthController {

    private final UserRepository userRepository;

    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ==================== LOGIN PAGE ====================
    @GetMapping("/")
    public String loginPage(Model model) {
        model.addAttribute("loginForm", new LoginForm());
        model.addAttribute("registerForm", new RegisterForm());
        return "index";
    }

    // ==================== LOGIN ====================
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, Model model) {
        User user = userRepository.findByUsername(username).orElse(null);

        // MITIGACIÓN: ya no se "descifra" la contraseña almacenada (antes con
        // AES/ECB y una clave embebida). Ahora se verifica la contraseña
        // ingresada contra el hash BCrypt guardado mediante
        // EncryptionService.matches(...), que recalcula el hash con la sal
        // incluida en el propio valor almacenado y compara de forma segura.
        if (user != null && EncryptionService.matches(password, user.getPassword())) {
            model.addAttribute("loginSuccess", true);
            model.addAttribute("welcomeUser", username);
            // MITIGACIÓN: ya no se expone la contraseña cifrada/hasheada en
            // la respuesta HTML. Mostrar el hash (aunque no sea reversible)
            // no aporta nada al usuario y solo da información innecesaria a
            // un posible atacante que intercepte o inspeccione la página.
            return "index";
        }

        model.addAttribute("loginError", "Usuario o contraseña incorrecta");
        addForms(model);
        return "index";
    }

    // ==================== REGISTER ====================
    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password,
                           @RequestParam String confirmPwd, Model model) {
        if (!password.equals(confirmPwd)) {
            model.addAttribute("registerError", "Las contraseñas no coinciden");
            addForms(model);
            return "index";
        }

        if (userRepository.findByUsername(username).isPresent()) {
            model.addAttribute("registerError", "El usuario ya existe");
            addForms(model);
            return "index";
        }


        com.cinebuscador.model.User nuevoUsuario = new com.cinebuscador.model.User();
        nuevoUsuario.setUsername(username);
        // MITIGACIÓN: se guarda un hash BCrypt (con sal aleatoria embebida en
        // el propio hash) en vez de un valor cifrado y reversible.
        nuevoUsuario.setPassword(EncryptionService.hashPassword(password));
        userRepository.save(nuevoUsuario);

        model.addAttribute("registerSuccess", true);
        model.addAttribute("registeredUsername", username);
        // MITIGACIÓN: no se devuelve el hash de la contraseña en la respuesta.
        addForms(model);
        return "index";
    }

    // ==================== FORM BEANS ====================
    public static class LoginForm {
        private String username, password;
        public String getUsername() { return username; }
        public void setUsername(String u) { username = u; }
        public String getPassword() { return password; }
        public void setPassword(String p) { password = p; }
    }

    public static class RegisterForm {
        private String username, password, confirmPwd;
        public String getUsername() { return username; }
        public void setUsername(String u) { username = u; }
        public String getPassword() { return password; }
        public void setPassword(String p) { password = p; }
        public String getConfirmPwd() { return confirmPwd; }
        public void setConfirmPwd(String c) { confirmPwd = c; }
    }

    private void addForms(Model model) {
        model.addAttribute("loginForm", new LoginForm());
        model.addAttribute("registerForm", new RegisterForm());
    }
}
