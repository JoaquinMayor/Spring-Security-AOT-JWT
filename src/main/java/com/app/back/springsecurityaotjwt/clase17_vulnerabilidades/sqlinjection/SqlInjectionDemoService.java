package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.sqlinjection;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * CLASE 17 - SQL INJECTION: la versión vulnerable y las versiones seguras, lado a lado.
 *
 * ¿Qué es? El atacante escribe CÓDIGO SQL dentro de un campo de texto. Si el servidor arma la
 * consulta pegando (concatenando) ese texto, la base de datos lo ejecuta como parte de la consulta.
 *
 * Ejemplo con  buscarVulnerable("x' OR '1'='1"):
 *
 *   SELECT ... FROM productos WHERE visible = TRUE AND nombre = 'x' OR '1'='1'
 *                                                              └──────┬───────┘
 *                                                    el atacante "cerró" la comilla y agregó
 *                                                    una condición que SIEMPRE es verdadera
 *   -> devuelve TODOS los productos, incluso los ocultos.
 *
 * Peor aún, con UNION puede leer OTRAS tablas:
 *   x' UNION SELECT id, username, password, 0 FROM usuarios --
 *   -> devuelve los usuarios y sus hashes de contraseña (¡por eso hay que hashear con BCrypt! Clase 16).
 *
 * La solución: CONSULTAS PARAMETRIZADAS (PreparedStatement). El SQL y los datos viajan por
 * separado; la base de datos sabe que el "?" es un DATO y nunca lo interpreta como código.
 */
@Service
public class SqlInjectionDemoService {

    private static final String COLUMNAS = "SELECT id, nombre, categoria, precio FROM productos ";

    private final JdbcTemplate jdbcTemplate;
    private final ProductoRepository productoRepository;

    public SqlInjectionDemoService(JdbcTemplate jdbcTemplate, ProductoRepository productoRepository) {
        this.jdbcTemplate = jdbcTemplate;
        this.productoRepository = productoRepository;
    }

    /** ❌ VULNERABLE: concatena la entrada del usuario dentro del SQL. NUNCA hagas esto. */
    public List<Map<String, Object>> buscarVulnerable(String nombre) {
        String sql = COLUMNAS + "WHERE visible = TRUE AND nombre = '" + nombre + "'";
        return jdbcTemplate.queryForList(sql);
    }

    /** ✅ SEGURO: consulta parametrizada con JDBC. El "?" se reemplaza de forma segura. */
    public List<Map<String, Object>> buscarSeguroJdbc(String nombre) {
        String sql = COLUMNAS + "WHERE visible = TRUE AND nombre = ?";
        return jdbcTemplate.queryForList(sql, nombre);
    }

    /** ✅ SEGURO (y lo más cómodo): consulta derivada de Spring Data JPA. */
    public List<ProductoDto> buscarSeguroJpa(String nombre) {
        return productoRepository.findByVisibleTrueAndNombre(nombre).stream().map(ProductoDto::from).toList();
    }
}
