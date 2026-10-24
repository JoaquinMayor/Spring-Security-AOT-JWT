package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.ejercicio;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * CLASE 16 - EJERCICIO N°1 / LIVE CODING: "Almacenamiento seguro de contraseñas con BCrypt".
 *
 * Consigna: implementar el registro de un usuario donde la contraseña se convierta en un hash
 * seguro con BCrypt, y luego validar su autenticidad al momento del login.
 *
 * Es una clase Java "pura" (sin Spring) a propósito, para entender BCrypt sin distracciones.
 * El test UsuarioServiceTest y el método main() la prueban con una contraseña correcta y otra incorrecta.
 */
public class UsuarioService {

    // Cost factor 12 -> 2^12 = 4096 iteraciones.
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    /** Registro: recibe la contraseña en texto plano y devuelve el hash que se guardaría en la BD. */
    public String registrar(String password) {
        return encoder.encode(password);
    }

    /**
     * Login: ¿la contraseña escrita corresponde a este hash?
     *
     * OJO: no se puede hacer  encoder.encode(password).equals(hash)  porque cada encode() usa una
     * SAL aleatoria distinta y da un hash distinto. matches() extrae la sal y el cost del hash
     * guardado, repite el cálculo con ellos y compara.
     */
    public boolean verificar(String password, String hash) {
        return encoder.matches(password, hash);
    }

    public static void main(String[] args) {
        UsuarioService service = new UsuarioService();

        String hash = service.registrar("MiClaveSegura123!");
        System.out.println("Hash generado:            " + hash);
        System.out.println("Mismo password, otro hash: " + service.registrar("MiClaveSegura123!") + "  <- distinto por la SAL");

        System.out.println("¿Contraseña correcta?   " + service.verificar("MiClaveSegura123!", hash));  // true
        System.out.println("¿Contraseña incorrecta? " + service.verificar("otraClave", hash));          // false
    }
}
