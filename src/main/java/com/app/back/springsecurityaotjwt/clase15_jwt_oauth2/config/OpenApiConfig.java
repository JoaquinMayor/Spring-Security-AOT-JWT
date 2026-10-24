package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * CLASE 15 - Swagger con autenticación Bearer (JWT).
 *
 * Con esta configuración, Swagger UI (http://localhost:8080/swagger-ui.html) muestra el botón
 * "Authorize". Ahí pegás el token que te devolvió /api/v1/auth/login y Swagger lo envía
 * automáticamente en el header "Authorization: Bearer <token>" de cada request.
 */
@Configuration
public class OpenApiConfig {

    private static final String SECURITY_SCHEME = "bearerAuth";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Seguridad en aplicaciones Java - Clases 15, 16 y 17")
                        .version("1.0.0")
                        .description("JWT y OAuth2 (Clase 15), credenciales y cifrado (Clase 16), "
                                + "prevención de vulnerabilidades (Clase 17)."))
                // Por defecto, todos los endpoints requieren el token...
                .addSecurityItem(new SecurityRequirement().addList(SECURITY_SCHEME))
                // ...y este es el "tipo" de token: HTTP Bearer con formato JWT.
                .components(new Components()
                        .addSecuritySchemes(SECURITY_SCHEME, new SecurityScheme()
                                .name(SECURITY_SCHEME)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));
    }
}
