package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.sqlinjection;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.math.BigDecimal;

/**
 * CLASE 17 - Entidad de ejemplo para las demos de SQL Injection y de paginación.
 * Los productos con visible = false son "secretos": un usuario normal nunca debería verlos.
 */
@Entity
@Table(name = "productos")
public class Producto {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String nombre;

    @Column(nullable = false)
    private String categoria;

    @Column(nullable = false)
    private BigDecimal precio;

    private boolean visible = true;

    protected Producto() {
    }

    public Producto(String nombre, String categoria, BigDecimal precio, boolean visible) {
        this.nombre = nombre;
        this.categoria = categoria;
        this.precio = precio;
        this.visible = visible;
    }

    public Long getId() {
        return id;
    }

    public String getNombre() {
        return nombre;
    }

    public String getCategoria() {
        return categoria;
    }

    public BigDecimal getPrecio() {
        return precio;
    }

    public boolean isVisible() {
        return visible;
    }
}
