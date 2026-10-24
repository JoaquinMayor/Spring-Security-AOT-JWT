package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.credenciales;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CredencialExternaRepository extends JpaRepository<CredencialExterna, Long> {

    List<CredencialExterna> findByPropietario(String propietario);

    /** Busca por id Y dueño: así un usuario nunca puede leer la credencial de otro. */
    Optional<CredencialExterna> findByIdAndPropietario(Long id, String propietario);
}
