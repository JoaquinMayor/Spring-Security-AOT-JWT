package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.paginacion;

import com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.sqlinjection.ProductoDto;
import com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.sqlinjection.ProductoRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.web.PagedModel;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CLASE 17 - BONUS: PAGINACIÓN (requiere JWT).
 *
 * ¿Qué pasa si la tabla tiene 1 millón de productos y hacemos findAll()? Se cargan TODOS en
 * memoria: respuesta lenta, mucho consumo de memoria y la base de datos sufre. Incluso puede
 * usarse como ataque de denegación de servicio.
 *
 * Con paginación pedimos de a "páginas":
 *   GET /api/clase17/productos?page=0&size=5&sort=precio,desc
 *   GET /api/clase17/productos?categoria=accesorios&page=1
 *
 *   totalPaginas = totalElementos / tamañoPagina   (ej.: 100 / 20 = 5)
 *
 * Además limitamos el tamaño máximo de página (MAX_PAGE_SIZE) para que nadie pida size=1000000.
 */
@RestController
@RequestMapping("/api/clase17/productos")
@Tag(name = "Clase 17 - Paginación", description = "Consultas por páginas con Pageable")
public class ProductoPaginadoController {

    private static final int MAX_PAGE_SIZE = 50;

    private final ProductoRepository repository;

    public ProductoPaginadoController(ProductoRepository repository) {
        this.repository = repository;
    }

    @Operation(summary = "Productos paginados (page, size, sort)")
    @GetMapping
    public PagedModel<ProductoDto> listar(
            @RequestParam(required = false) @Pattern(regexp = "^[a-z]{1,30}$") String categoria,
            @PageableDefault(size = 5, sort = "nombre", direction = Sort.Direction.ASC) Pageable pageable) {

        Pageable seguro = PageRequest.of(pageable.getPageNumber(),
                Math.min(pageable.getPageSize(), MAX_PAGE_SIZE), pageable.getSort());

        Page<ProductoDto> page = (categoria == null
                ? repository.findByVisibleTrue(seguro)
                : repository.findByVisibleTrueAndCategoria(categoria, seguro))
                .map(ProductoDto::from);

        // PagedModel: formato JSON estable para páginas (content + page{size, number, totalElements, totalPages}).
        return new PagedModel<>(page);
    }
}
