package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.sqlinjection;

import java.math.BigDecimal;

/**
 * CLASE 17 - DTO (Data Transfer Object): lo que exponemos al cliente.
 * Nunca devolvemos la entidad directamente: así controlamos exactamente qué campos salen.
 */
public record ProductoDto(Long id, String nombre, String categoria, BigDecimal precio) {

    public static ProductoDto from(Producto p) {
        return new ProductoDto(p.getId(), p.getNombre(), p.getCategoria(), p.getPrecio());
    }
}
