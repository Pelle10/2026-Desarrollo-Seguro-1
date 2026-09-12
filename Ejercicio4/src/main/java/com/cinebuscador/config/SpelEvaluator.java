package com.cinebuscador.config;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Component;

// MITIGACIÓN (CWE-1336 - Server-Side Template Injection / SpEL Injection):
// La causa raíz de la vulnerabilidad era evaluar como expresión SpEL un texto
// que llega directamente del usuario (parámetro "buscar" del formulario de
// búsqueda), usando además un StandardEvaluationContext con acceso a
// System/Runtime, lo cual habilita ejecución de código arbitrario en el
// servidor (por ejemplo T(java.lang.Runtime).getRuntime().exec(...)).
//
// La solución correcta NO es "sanitizar" el string antes de evaluarlo (hay
// demasiadas formas de construir una expresión maliciosa), sino eliminar por
// completo la evaluación de SpEL sobre datos de entrada no confiables:
// ver FuncionController, que ahora compara el texto de búsqueda directamente
// como String en vez de pasarlo por este evaluador.
//
// Esta clase se conserva únicamente como referencia de qué NO hacer y, si en
// algún momento se necesitara evaluar expresiones controladas por el propio
// desarrollador (nunca por el usuario final), debería usarse
// SimpleEvaluationContext (sandboxed, sin acceso a clases del sistema) en
// lugar de StandardEvaluationContext, y jamás exponer System/Runtime.
@Component
public class SpelEvaluator {


    public String evaluate(String expression) {
        if (expression == null || expression.isBlank()) {
            return "";
        }

        ExpressionParser parser = new SpelExpressionParser();
        
        org.springframework.expression.EvaluationContext context =
            SimpleEvaluationContext.forReadOnlyDataBinding().build();

        StandardEvaluationContext standardContext = new StandardEvaluationContext();


        standardContext.setVariable("system", System.class);
        standardContext.setVariable("runtime", Runtime.class);

        var expr = parser.parseExpression(expression);
        Object result = expr.getValue(standardContext);

        return result != null ? result.toString() : "";
    }
}
