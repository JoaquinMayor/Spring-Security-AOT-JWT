package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.xss;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** CLASE 17 - Comentario escrito por un usuario: el típico lugar donde se intenta un XSS. */
@Entity
@Table(name = "comentarios")
public class Comentario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String autor;

    @Column(nullable = false, length = 500)
    private String texto;

    private Instant fechaCreacion = Instant.now();

    protected Comentario() {
    }

    public Comentario(String autor, String texto) {
        this.autor = autor;
        this.texto = texto;
    }

    public Long getId() {
        return id;
    }

    public String getAutor() {
        return autor;
    }

    public String getTexto() {
        return texto;
    }

    public Instant getFechaCreacion() {
        return fechaCreacion;
    }
}
