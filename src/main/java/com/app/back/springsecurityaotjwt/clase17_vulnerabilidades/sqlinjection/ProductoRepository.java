package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.sqlinjection;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * CLASE 17 - Formas SEGURAS de consultar la base de datos con Spring Data.
 *
 * | Estrategia                          | ¿Segura?  | Comentario                                  |
 * |-------------------------------------|-----------|---------------------------------------------|
 * | Consulta derivada (nombre de método)| ✅ Sí      | La preferida: Spring trata los parámetros   |
 * |                                     |           | como DATOS, nunca como código               |
 * | @Query con parámetros (:nombre, ?1) | ✅ Sí      | Seguro mientras NO concatenes strings       |
 * | SQL armado concatenando strings     | ❌ NO      | Ver SqlInjectionDemoService.buscarVulnerable|
 */
public interface ProductoRepository extends JpaRepository<Producto, Long> {

    /** Consulta derivada: Spring genera "WHERE visible = true AND nombre = ?" con parámetros. */
    List<Producto> findByVisibleTrueAndNombre(String nombre);

    /** @Query con parámetro con nombre: también seguro, el valor se envía separado del SQL. */
    @Query("SELECT p FROM Producto p WHERE p.visible = true AND LOWER(p.nombre) LIKE LOWER(CONCAT('%', :texto, '%'))")
    List<Producto> buscarPorTexto(@Param("texto") String texto);

    /** BONUS paginación: devuelve una "página" de resultados en lugar de todos. */
    Page<Producto> findByVisibleTrueAndCategoria(String categoria, Pageable pageable);

    Page<Producto> findByVisibleTrue(Pageable pageable);
}
