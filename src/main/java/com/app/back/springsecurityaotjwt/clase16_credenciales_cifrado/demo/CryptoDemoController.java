package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.demo;

import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.crypto.AesGcmEncryptionService;
import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.crypto.CryptoUtilBasico;
import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.hashing.HashingUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CLASE 16 - Endpoints PÚBLICOS para experimentar en clase con hashing y cifrado.
 *
 * Se usan POST con body JSON (y no GET con ?texto=...) porque los parámetros de la URL quedan
 * guardados en logs, historial del navegador y proxies: nunca mandes secretos por la URL.
 *
 * ⚠ Son endpoints didácticos. En una app real nunca expondrías un "cifrador" público.
 */
@RestController
@RequestMapping("/api/clase16/demo")
@Tag(name = "Clase 16 - Demos de hashing y cifrado", description = "Endpoints didácticos públicos")
@SecurityRequirements
public class CryptoDemoController {

    public record Texto(@NotBlank @Size(max = 500) String texto) {
    }

    public record VerificarHash(@NotBlank @Size(max = 64) String texto, @NotBlank String hash) {
    }

    private final AesGcmEncryptionService aes;
    // Cost 10 en la demo para que responda rápido; la app real usa 12 (ver PasswordEncoderConfig).
    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(10);

    public CryptoDemoController(AesGcmEncryptionService aes) {
        this.aes = aes;
    }

    @Operation(summary = "Hashing: SHA-256 sin sal vs. con sal")
    @PostMapping("/hash")
    public Map<String, Object> hash(@Valid @RequestBody Texto body) {
        String salt1 = HashingUtil.generateSalt();
        String salt2 = HashingUtil.generateSalt();
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("sha256Hex", HashingUtil.sha256Hex(body.texto()));
        r.put("sha256Base64", HashingUtil.sha256Base64(body.texto()));
        r.put("observacion1", "Si repetís la request, el SHA-256 sin sal da SIEMPRE lo mismo");
        r.put("sha256ConSal_1", Map.of("sal", salt1, "hash", HashingUtil.sha256WithSalt(body.texto(), salt1)));
        r.put("sha256ConSal_2", Map.of("sal", salt2, "hash", HashingUtil.sha256WithSalt(body.texto(), salt2)));
        r.put("observacion2", "Con sal, el mismo texto produce hashes distintos");
        return r;
    }

    @Operation(summary = "BCrypt: generar dos hashes de la misma contraseña")
    @PostMapping("/bcrypt")
    public Map<String, Object> bcrypt(@Valid @RequestBody Texto body) {
        long inicio = System.currentTimeMillis();
        String hash1 = bcrypt.encode(body.texto());
        long ms = System.currentTimeMillis() - inicio;
        String hash2 = bcrypt.encode(body.texto());
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("hash1", hash1);
        r.put("hash2", hash2);
        r.put("milisegundosPorHash", ms);
        r.put("formato", "$2a$<cost>$<22 caracteres de sal><31 caracteres de hash>");
        r.put("observacion", "Los dos hashes son distintos (sal automática) pero ambos validan la misma contraseña");
        return r;
    }

    @Operation(summary = "BCrypt: verificar una contraseña contra un hash con matches()")
    @PostMapping("/bcrypt/verificar")
    public Map<String, Object> verificar(@Valid @RequestBody VerificarHash body) {
        return Map.of("coincide", bcrypt.matches(body.texto(), body.hash()));
    }

    @Operation(summary = "Cifrado AES: versión básica de la diapositiva vs. AES-GCM")
    @PostMapping("/aes/cifrar")
    public Map<String, Object> cifrar(@Valid @RequestBody Texto body) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("aesBasico_ECB_1", CryptoUtilBasico.encrypt(body.texto()));
        r.put("aesBasico_ECB_2", CryptoUtilBasico.encrypt(body.texto()));
        r.put("observacionBasico", "Mismo texto -> mismo cifrado: filtra patrones (modo ECB). No usar.");
        r.put("aesGcm_1", aes.encrypt(body.texto()));
        r.put("aesGcm_2", aes.encrypt(body.texto()));
        r.put("observacionGcm", "IV aleatorio: mismo texto -> cifrados distintos. Ambos se descifran bien.");
        return r;
    }

    @Operation(summary = "Descifrar un texto cifrado con AES-GCM (si fue alterado, falla)")
    @PostMapping("/aes/descifrar")
    public Map<String, Object> descifrar(@Valid @RequestBody Texto body) {
        return Map.of("textoOriginal", aes.decrypt(body.texto()));
    }
}
