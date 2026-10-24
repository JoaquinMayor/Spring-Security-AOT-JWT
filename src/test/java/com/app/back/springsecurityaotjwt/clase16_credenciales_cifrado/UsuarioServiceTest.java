package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado;

import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.ejercicio.UsuarioService;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CLASE 16 - Ejercicio N°1: el hash nunca es la contraseña, la misma contraseña da hashes
 * distintos (sal) y matches() valida correctamente.
 */
class UsuarioServiceTest {

    private final UsuarioService service = new UsuarioService();

    @Test
    void registrarDevuelveUnHashBCryptYNoLaContrasena() {
        String hash = service.registrar("MiClaveSegura123!");
        assertThat(hash).startsWith("$2a$12$").doesNotContain("MiClaveSegura123!");
    }

    @Test
    void laMismaContrasenaGeneraHashesDistintosPorLaSal() {
        assertThat(service.registrar("igual")).isNotEqualTo(service.registrar("igual"));
    }

    @Test
    void verificarAceptaLaCorrectaYRechazaLaIncorrecta() {
        String hash = service.registrar("MiClaveSegura123!");
        assertThat(service.verificar("MiClaveSegura123!", hash)).isTrue();
        assertThat(service.verificar("otraClave", hash)).isFalse();
    }
}
