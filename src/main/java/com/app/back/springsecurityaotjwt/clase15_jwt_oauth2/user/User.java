package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CLASE 15 - PASO 2: el usuario implementa {@link UserDetails}.
 *
 * ¿Por qué? Spring Security no conoce NUESTRA clase User. Habla un "idioma común":
 * la interfaz UserDetails. Al implementarla le decimos a Spring:
 *   - getUsername()     -> cuál es el identificador del usuario (acá, el email)
 *   - getPassword()     -> cuál es su contraseña (¡el HASH, nunca el texto plano! ver Clase 16)
 *   - getAuthorities()  -> qué roles/permisos tiene
 *   - isEnabled() ...   -> si la cuenta está activa, bloqueada, vencida, etc.
 *
 * Así el AuthenticationManager puede validar a cualquier usuario sin saber cómo lo guardamos.
 */
@Entity
@Table(name = "usuarios") // "user" es palabra reservada en varias bases de datos
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    /** Hash BCrypt de la contraseña (Clase 16). Nunca se guarda la contraseña original. */
    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "usuario_roles", joinColumns = @JoinColumn(name = "usuario_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "rol")
    private Set<Role> roles = new HashSet<>();

    private boolean active = true;

    protected User() {
        // requerido por JPA
    }

    public User(String username, String passwordHash, Set<Role> roles) {
        this.username = username;
        this.password = passwordHash;
        this.roles = new HashSet<>(roles);
    }

    /**
     * Convierte nuestros roles (USER, ADMIN) en "authorities" que Spring entiende
     * (ROLE_USER, ROLE_ADMIN). Estos son los permisos que viajan dentro del SecurityContext.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isEnabled() {
        return active;
    }

    public Long getId() {
        return id;
    }

    public Set<Role> getRoles() {
        return roles;
    }
}
