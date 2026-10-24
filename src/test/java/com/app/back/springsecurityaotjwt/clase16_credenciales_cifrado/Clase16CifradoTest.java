package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado;

import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.crypto.AesGcmEncryptionService;
import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.crypto.CryptoUtilBasico;
import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.hashing.HashingUtil;
import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.password.PepperedPasswordEncoder;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** CLASE 16 - Hashing, BCrypt + pepper, AES y almacenamiento cifrado. */
@SpringBootTest
@AutoConfigureMockMvc
class Clase16CifradoTest {

    @Autowired
    private AesGcmEncryptionService aes;

    @Autowired
    private MockMvc mvc;

    @Test
    void sha256EsDeterministaYConSalCambia() {
        assertThat(HashingUtil.sha256Hex("hola")).isEqualTo(HashingUtil.sha256Hex("hola")).hasSize(64);
        assertThat(HashingUtil.sha256WithSalt("hola", HashingUtil.generateSalt()))
                .isNotEqualTo(HashingUtil.sha256WithSalt("hola", HashingUtil.generateSalt()));
        assertThat(HashingUtil.verifyIntegrity("hola", HashingUtil.sha256Hex("hola"))).isTrue();
        assertThat(HashingUtil.verifyIntegrity("hola!", HashingUtil.sha256Hex("hola"))).isFalse();
    }

    @Test
    void pepperCambiaElResultado() {
        PepperedPasswordEncoder conPepperA = new PepperedPasswordEncoder(new BCryptPasswordEncoder(4), "pepper-A-1234567890");
        PepperedPasswordEncoder conPepperB = new PepperedPasswordEncoder(new BCryptPasswordEncoder(4), "pepper-B-1234567890");
        String hash = conPepperA.encode("Clave123!");
        assertThat(conPepperA.matches("Clave123!", hash)).isTrue();
        // Si roban la BD pero no el pepper, el hash no se puede validar.
        assertThat(conPepperB.matches("Clave123!", hash)).isFalse();
    }

    @Test
    void aesBasicoEsDeterministaPeroGcmNo() throws Exception {
        assertThat(CryptoUtilBasico.encrypt("hola")).isEqualTo(CryptoUtilBasico.encrypt("hola"));
        assertThat(CryptoUtilBasico.decrypt(CryptoUtilBasico.encrypt("hola"))).isEqualTo("hola");

        String c1 = aes.encrypt("4111-1111-1111-1111");
        String c2 = aes.encrypt("4111-1111-1111-1111");
        assertThat(c1).isNotEqualTo(c2);
        assertThat(aes.decrypt(c1)).isEqualTo("4111-1111-1111-1111");
    }

    @Test
    void aesGcmDetectaManipulacion() {
        String cifrado = aes.encrypt("dato sensible");
        char[] chars = cifrado.toCharArray();
        chars[20] = chars[20] == 'A' ? 'B' : 'A';
        assertThatThrownBy(() -> aes.decrypt(new String(chars))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void registroRechazaContrasenaDebil() throws Exception {
        mvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"debil@example.com\",\"password\":\"123456\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errores.password").exists());
    }

    @Test
    void credencialSeGuardaCifradaEnLaBaseDeDatos() throws Exception {
        String body = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"user@example.com\",\"password\":\"User123!\"}"))
                .andReturn().getResponse().getContentAsString();
        String token = "Bearer " + JsonPath.read(body, "$.token");

        mvc.perform(post("/api/clase16/credenciales").header("Authorization", token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"servicio\":\"github\",\"tokenApi\":\"ghp_tokenSuperSecreto1234\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.tokenEnmascarado").value("****1234"));

        // En la BD la columna NO contiene el token original.
        mvc.perform(get("/api/clase16/credenciales/como-se-ve-en-la-bd").header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].TOKEN_API").value(not("ghp_tokenSuperSecreto1234")));
    }
}
