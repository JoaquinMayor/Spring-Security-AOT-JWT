package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * CLASE 15 - Pruebas del flujo JWT completo: login -> token -> endpoint protegido.
 * Son el equivalente automático de lo que se hace a mano con Postman en el live coding.
 */
@SpringBootTest
@AutoConfigureMockMvc
class Clase15JwtOAuth2Test {

    @Autowired
    private MockMvc mvc;

    private String login(String username, String password) throws Exception {
        String body = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.token");
    }

    @Test
    void loginCorrectoDevuelveUnJwtConTresPartes() throws Exception {
        String token = login("user@example.com", "User123!");
        // header.payload.firma
        org.assertj.core.api.Assertions.assertThat(token.split("\\.")).hasSize(3);
    }

    @Test
    void loginConContrasenaIncorrectaDevuelve401() throws Exception {
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"user@example.com\",\"password\":\"incorrecta\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Usuario o contraseña incorrectos"));
    }

    @Test
    void endpointProtegidoConTokenValidoDevuelve200() throws Exception {
        String token = login("user@example.com", "User123!");
        mvc.perform(get("/api/test/authenticated").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.usuario").value("user@example.com"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    void endpointProtegidoSinTokenDevuelve401() throws Exception {
        mvc.perform(get("/api/test/authenticated")).andExpect(status().isUnauthorized());
    }

    @Test
    void tokenAlteradoDevuelve401() throws Exception {
        String token = login("user@example.com", "User123!");
        String alterado = token.substring(0, token.length() - 3) + "abc"; // rompemos la firma
        mvc.perform(get("/api/test/authenticated").header("Authorization", "Bearer " + alterado))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registroCreaUsuarioYDevuelveToken() throws Exception {
        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"nuevo@example.com\",\"password\":\"Nuevo123!\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void parteWebRedirigeAlLoginSiNoHaySesion() throws Exception {
        mvc.perform(get("/profile"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/login")));
    }
}
