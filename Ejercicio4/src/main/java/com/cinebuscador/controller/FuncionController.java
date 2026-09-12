package com.cinebuscador.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.cinebuscador.model.Funcion;
import com.cinebuscador.repository.FuncionRepository;

@Controller
public class FuncionController {

    private final FuncionRepository funcionRepo;

    // MITIGACIÓN (CWE-1336 - SSTI / SpEL Injection):
    // Ya no se inyecta ni se usa SpelEvaluator para procesar el texto de
    // búsqueda. El parámetro "buscar" ahora se trata siempre como un simple
    // String de datos, nunca como código/expresión a evaluar. Esto elimina la
    // vulnerabilidad de raíz en vez de intentar "filtrar" caracteres
    // peligrosos de la expresión SpEL.
    @Autowired
    public FuncionController(FuncionRepository funcionRepo) {
        this.funcionRepo = funcionRepo;
    }

    @GetMapping("/")
    public String search(@RequestParam(required = false) String buscar, Model model) {

        model.addAttribute("query", buscar != null ? buscar : "");

        if (buscar == null || buscar.isBlank()) {
            // Mostrar todas las funciones si no hay busqueda
            List<Funcion> todas = funcionRepo.findAll();
            model.addAttribute("resultados", todas);
            model.addAttribute("mensaje", "Mostrando todas las funciones.");
            return "index";
        }

        // El texto ingresado por el usuario se usa tal cual, como dato de
        // comparación de String, nunca como expresión a evaluar.
        String textoBusqueda = buscar.trim();

        List<Funcion> resultados = funcionRepo.findAll().stream()
            .filter(f -> f.getNombreFuncion() != null &&
                         f.getNombreFuncion().toLowerCase().contains(textoBusqueda.toLowerCase()))
            .collect(Collectors.toList());

        if (!resultados.isEmpty()) {
            model.addAttribute("resultados", resultados);
            model.addAttribute("mensaje", "Resultados buscando por: " + textoBusqueda);
        } else {
            model.addAttribute("resultados", new ArrayList<Funcion>());
            model.addAttribute("mensaje", "No se encontraron coincidencias.");
        }

        return "index";
    }
}
