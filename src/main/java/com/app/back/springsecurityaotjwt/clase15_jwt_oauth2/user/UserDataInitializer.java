package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

/**
 * CLASE 15 - Usuarios de prueba para las clases (solo fuera del perfil "prod").
 *
 *   user@example.com  / User123!   -> rol USER
 *   admin@example.com / Admin123!  -> roles USER y ADMIN
 *
 * Las contraseñas se guardan hasheadas con BCrypt (Clase 16), igual que en un registro real.
 */
@Configuration
@Profile("!prod")
public class UserDataInitializer {

    private static final Logger log = LoggerFactory.getLogger(UserDataInitializer.class);

    @Bean
    ApplicationRunner seedUsers(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.count() > 0) {
                return;
            }
            userRepository.save(new User("user@example.com", passwordEncoder.encode("User123!"), Set.of(Role.USER)));
            userRepository.save(new User("admin@example.com", passwordEncoder.encode("Admin123!"), Set.of(Role.USER, Role.ADMIN)));
            log.info("Usuarios de prueba creados: user@example.com / User123!  y  admin@example.com / Admin123!");
        };
    }
}
