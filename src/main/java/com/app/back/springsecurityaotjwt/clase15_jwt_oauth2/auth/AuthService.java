package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth;

import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto.AuthRequest;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto.AuthResponse;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto.RegisterRequest;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.jwt.JwtService;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user.Role;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user.User;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

/**
 * CLASE 15 - PASO 5: AuthService. El núcleo de la autenticación.
 *
 *  register(): crea el usuario con la contraseña HASHEADA (Clase 16) y le devuelve un JWT.
 *  authenticate(): valida usuario + contraseña con el AuthenticationManager y, si son
 *                  correctos, genera un JWT.
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final long expirationMs;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager,
                       JwtService jwtService,
                       @Value("${app.jwt.expiration-ms}") long expirationMs) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.expirationMs = expirationMs;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // 1. Verificamos que el usuario no exista.
        if (userRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyExistsException();
        }
        // 2. Guardamos el HASH de la contraseña, nunca el texto plano (Clase 16).
        //    Todo usuario que se registra solo tiene rol USER (principio de mínimo privilegio, Clase 17).
        User user = new User(request.username(), passwordEncoder.encode(request.password()), Set.of(Role.USER));
        userRepository.save(user);
        // 3. Le devolvemos un token para que no tenga que loguearse de nuevo.
        return AuthResponse.bearer(jwtService.generateToken(user), expirationMs);
    }

    public AuthResponse authenticate(AuthRequest request) {
        // El AuthenticationManager hace todo el trabajo pesado:
        //   busca al usuario (UserDetailsService) y compara la contraseña con el hash (PasswordEncoder).
        // Si algo falla lanza BadCredentialsException -> el GlobalExceptionHandler responde 401.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        UserDetails user = (UserDetails) authentication.getPrincipal();
        return AuthResponse.bearer(jwtService.generateToken(user), expirationMs);
    }
}
