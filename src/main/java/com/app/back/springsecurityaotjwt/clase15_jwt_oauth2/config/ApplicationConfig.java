package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.config;

import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * CLASE 15 - ApplicationConfig: las "piezas" de autenticación de Spring Security.
 *
 * Así funciona la arquitectura (ver diagrama en el README):
 *
 *   Filtro --> AuthenticationManager --> AuthenticationProvider --> UserDetailsService (busca el usuario)
 *                                                               \-> PasswordEncoder    (compara la contraseña)
 *
 *  1. UserDetailsService:      sabe BUSCAR un usuario por su username (en nuestro caso, en la BD).
 *  2. PasswordEncoder:         sabe COMPARAR la contraseña escrita con el hash guardado (Clase 16).
 *  3. AuthenticationProvider:  junta las dos piezas anteriores (DaoAuthenticationProvider = "usuario en BD").
 *  4. AuthenticationManager:   es el "jefe": recibe el pedido de login y lo delega en los providers.
 */
@Configuration
public class ApplicationConfig {

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                // Mensaje genérico: no le decimos al atacante si el usuario existe o no.
                .orElseThrow(() -> new UsernameNotFoundException("Credenciales inválidas"));
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        // El PasswordEncoder viene de la Clase 16 (BCrypt + pepper).
        provider.setPasswordEncoder(passwordEncoder);
        // ProviderManager es la implementación estándar de AuthenticationManager: recorre sus providers.
        return new ProviderManager(provider);
    }
}
