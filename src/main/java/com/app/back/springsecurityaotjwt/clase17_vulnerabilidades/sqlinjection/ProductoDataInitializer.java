package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.sqlinjection;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * CLASE 17 - Datos de ejemplo: productos visibles, 2 productos OCULTOS (para la demo de
 * SQL Injection) y suficientes productos para que la paginación tenga varias páginas.
 */
@Configuration
@Profile("!prod")
public class ProductoDataInitializer {

    @Bean
    ApplicationRunner seedProductos(ProductoRepository repository) {
        return args -> {
            if (repository.count() > 0) {
                return;
            }
            List<Producto> productos = new ArrayList<>();
            productos.add(new Producto("Teclado", "perifericos", new BigDecimal("25000"), true));
            productos.add(new Producto("Mouse", "perifericos", new BigDecimal("12000"), true));
            productos.add(new Producto("Monitor", "pantallas", new BigDecimal("180000"), true));
            productos.add(new Producto("Prototipo secreto X", "interno", new BigDecimal("999999"), false));
            productos.add(new Producto("Lista de precios mayoristas", "interno", new BigDecimal("1"), false));
            for (int i = 1; i <= 30; i++) {
                productos.add(new Producto("Cable USB modelo " + i, "accesorios", new BigDecimal(1000 + i * 100), true));
            }
            repository.saveAll(productos);
        };
    }
}
