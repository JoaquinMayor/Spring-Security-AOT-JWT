package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * CLASE 15 - Acceso a la base de datos de usuarios.
 *
 * Fijate que los métodos son "consultas derivadas": Spring arma la consulta a partir del nombre
 * del método. Además de ser cómodo, es SEGURO contra inyección (ver Clase 17), porque los
 * parámetros siempre se tratan como datos y nunca como parte del código SQL.
 */
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);
}
