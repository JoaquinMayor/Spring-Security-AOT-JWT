package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** CLASE 17 - SQL/NoSQL Injection, XSS, CSRF, headers, mínimo privilegio y paginación. */
@SpringBootTest
@AutoConfigureMockMvc
class Clase17VulnerabilidadesTest {

    private static final String ATAQUE_SQL = "x' OR '1'='1";

    @Autowired
    private MockMvc mvc;

    private String bearer(String username, String password) throws Exception {
        String body = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andReturn().getResponse().getContentAsString();
        return "Bearer " + JsonPath.read(body, "$.token");
    }

    // ----------------------------- SQL Injection -----------------------------

    @Test
    void sqlInjectionFuncionaEnElEndpointVulnerable() throws Exception {
        // Devuelve TODOS los productos (35), incluidos los ocultos.
        mvc.perform(get("/api/clase17/sql/vulnerable").param("nombre", ATAQUE_SQL))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(greaterThan(30)));
    }

    @Test
    void sqlInjectionUnionFiltraLosHashesDeUsuarios() throws Exception {
        mvc.perform(get("/api/clase17/sql/vulnerable")
                        .param("nombre", "x' UNION SELECT id, username, password, 0 FROM usuarios --"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].CATEGORIA").value(org.hamcrest.Matchers.hasItem(containsString("$2a$"))));
    }

    @Test
    void sqlInjectionNoFuncionaConConsultasParametrizadas() throws Exception {
        mvc.perform(get("/api/clase17/sql/seguro").param("nombre", ATAQUE_SQL))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
        mvc.perform(get("/api/clase17/sql/seguro-jpa").param("nombre", ATAQUE_SQL))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
        mvc.perform(get("/api/clase17/sql/seguro-jpa").param("nombre", "Teclado"))
                .andExpect(jsonPath("$", hasSize(1)));
    }

    // ----------------------------- NoSQL Injection -----------------------------

    @Test
    void noSqlInjectionConOperadorNeEntraSinContrasena() throws Exception {
        mvc.perform(post("/api/clase17/nosql/login-vulnerable").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resultado").value(containsString("LOGIN EXITOSO")));
    }

    @Test
    void noSqlInjectionEsRechazadaPorElDtoTipado() throws Exception {
        mvc.perform(post("/api/clase17/nosql/login-seguro").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void idDeDocumentoInvalidoEsRechazado() throws Exception {
        mvc.perform(get("/api/clase17/nosql/documentos/{id}", "a$b"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/clase17/nosql/documentos/u1"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.username").value("admin"));
    }

    // ----------------------------- XSS -----------------------------

    @Test
    void comentarioConScriptSeDevuelveEscapado() throws Exception {
        String token = bearer("user@example.com", "User123!");
        mvc.perform(post("/api/clase17/comentarios").header("Authorization", token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"texto\":\"<script>alert('XSS')</script>\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.texto").value("&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"));
    }

    @Test
    void respuestasIncluyenHeadersDeSeguridad() throws Exception {
        mvc.perform(get("/clase17/xss-demo.html"))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-XSS-Protection", "1; mode=block"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
        mvc.perform(get("/clase17/xss-demo-sin-csp.html"))
                .andExpect(header().doesNotExist("Content-Security-Policy"));
    }

    // ----------------------------- CSRF -----------------------------

    @Test
    void postWebSinTokenCsrfEsRechazado() throws Exception {
        mvc.perform(post("/web/transferencias").with(user("user@example.com"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"destino\":\"ATACANTE\",\"monto\":999}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void postWebConTokenCsrfEsAceptado() throws Exception {
        mvc.perform(post("/web/transferencias").with(user("user@example.com")).with(csrf().asHeader())
                        .session(new MockHttpSession())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"destino\":\"AMIGO\",\"monto\":100}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resultado").value(containsString("Transferencia realizada")));
    }

    @Test
    void apiConJwtNoNecesitaCsrf() throws Exception {
        // POST a la API sin token CSRF: funciona porque la API es stateless y usa JWT en el header.
        String token = bearer("user@example.com", "User123!");
        mvc.perform(post("/api/clase17/comentarios").header("Authorization", token)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"texto\":\"hola\"}"))
                .andExpect(status().isCreated());
    }

    // ----------------------------- Mínimo privilegio -----------------------------

    @Test
    void endpointAdminRechazaAUsuarioComunYAceptaAdmin() throws Exception {
        mvc.perform(get("/api/clase17/admin/usuarios").header("Authorization", bearer("user@example.com", "User123!")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/clase17/admin/usuarios").header("Authorization", bearer("admin@example.com", "Admin123!")))
                .andExpect(status().isOk());
    }

    // ----------------------------- Paginación -----------------------------

    @Test
    void paginacionDevuelveUnaPaginaYLimitaElTamano() throws Exception {
        String token = bearer("user@example.com", "User123!");
        mvc.perform(get("/api/clase17/productos").header("Authorization", token)
                        .param("categoria", "accesorios").param("page", "1").param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(10)))
                .andExpect(jsonPath("$.page.totalElements").value(30))
                .andExpect(jsonPath("$.page.totalPages").value(3));

        mvc.perform(get("/api/clase17/productos").header("Authorization", token).param("size", "100000"))
                .andExpect(jsonPath("$.page.size").value(50));
    }

    @Test
    void errorInternoNoRevelaDetalles() throws Exception {
        mvc.perform(get("/api/clase17/productos").header("Authorization", bearer("user@example.com", "User123!"))
                        .param("sort", "campoInexistente"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Campo de ordenamiento inválido"));
    }
}
