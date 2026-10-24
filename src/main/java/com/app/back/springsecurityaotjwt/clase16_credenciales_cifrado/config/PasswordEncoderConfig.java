package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.config;

import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.password.PepperedPasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * CLASE 16 - El PasswordEncoder que usa TODA la aplicación (registro, login, formulario web).
 *
 * BCrypt con "cost factor" 12: el algoritmo se repite 2^12 = 4096 veces.
 *  - Para un usuario legítimo, tardar ~0,25 s en loguearse es imperceptible.
 *  - Para un atacante que quiere probar MILES DE MILLONES de contraseñas, es un muro.
 *  - Cuando las computadoras sean más rápidas, subimos el cost (13, 14...) y listo: es "adaptativo".
 *
 * Un hash BCrypt se ve así:   $2a$12$7v1xRp1XGHqrlqvhz3S4HuF.zv9PRAwOB8yWliZ08VvKnkhUd3X4a
 *                             └┬┘└┬┘└────────┬─────────┘└──────────────┬──────────────┘
 *                            tipo cost     sal (22 car.)            hash resultante
 * Por eso no hace falta guardar la sal aparte: viaja dentro del propio hash.
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder(@Value("${app.security.bcrypt-strength}") int strength,
                                           @Value("${app.security.password-pepper}") String pepper) {
        return new PepperedPasswordEncoder(new BCryptPasswordEncoder(strength), pepper);
    }
}
