package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * CLASE 17 - Principio de MÍNIMO PRIVILEGIO a nivel de método.
 *
 * Cada usuario debe tener SOLO los permisos que necesita, nada más.
 * @EnableMethodSecurity habilita anotaciones como:
 *
 *     @PreAuthorize("hasRole('ADMIN')")      // solo administradores
 *     @PreAuthorize("hasAnyRole('USER','ADMIN')")
 *     @PreAuthorize("#username == authentication.name")  // solo el propio usuario
 *
 * Diferencia con SecurityConfig: allá protegemos RUTAS (URLs); acá protegemos MÉTODOS.
 * Son capas complementarias (defensa en profundidad). Ejemplo de uso: AdminController.
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {
}
