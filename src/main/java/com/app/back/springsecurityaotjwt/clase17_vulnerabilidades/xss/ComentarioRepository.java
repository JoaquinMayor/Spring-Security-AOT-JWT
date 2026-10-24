package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.xss;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ComentarioRepository extends JpaRepository<Comentario, Long> {

    List<Comentario> findTop50ByOrderByFechaCreacionDesc();
}
