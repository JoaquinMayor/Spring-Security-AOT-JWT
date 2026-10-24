# Seguridad en aplicaciones Java con Spring Boot

### Clases 15, 16 y 17 · Java Nivel 2 | BBVA

Proyecto de práctica que lleva a código los temas de tres clases:

| Clase | Tema | Paquete con el código |
|---|---|---|
| **15** | Autenticación con **JWT** y **OAuth2** | [`clase15_jwt_oauth2`](src/main/java/com/app/back/springsecurityaotjwt/clase15_jwt_oauth2/) |
| **16** | Gestión de **credenciales** y **cifrado** | [`clase16_credenciales_cifrado`](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/) |
| **17** | **Prevención de vulnerabilidades** (CSRF, SQL/NoSQL Injection, XSS) | [`clase17_vulnerabilidades`](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/) |

Cada clase Java tiene comentarios en español que explican **qué hace, por qué se hace así y qué hay que tener en cuenta**. Están escritos para alguien que recién empieza.

📄 Documentos extra:

- [docs/COMO_PROBAR.md](docs/COMO_PROBAR.md): guía paso a paso para probar cada clase.
- [docs/Clase_15_Guia_Docente.md](docs/Clase_15_Guia_Docente.md), [docs/Clase_16_Guia_Docente.md](docs/Clase_16_Guia_Docente.md) y [docs/Clase_17_Guia_Docente.md](docs/Clase_17_Guia_Docente.md): guías para dar cada clase.
- [http/](http/): requests listos para ejecutar desde IntelliJ o VS Code.

---

## Índice

1. [Cómo arrancar el proyecto](#1-cómo-arrancar-el-proyecto)
2. [Mapa del proyecto](#2-mapa-del-proyecto)
3. [Clase 15: Autenticación con JWT y OAuth2](#3-clase-15--autenticación-con-jwt-y-oauth2)
4. [Clase 16: Gestión de credenciales y cifrado](#4-clase-16--gestión-de-credenciales-y-cifrado)
5. [Clase 17: Prevención de vulnerabilidades](#5-clase-17--prevención-de-vulnerabilidades)
6. [Glosario rápido](#6-glosario-rápido)

---

## 1. Cómo arrancar el proyecto

**Requisitos:** Java 21 o superior. No hace falta instalar Maven (viene `mvnw`) ni una base de datos (se usa **H2 en memoria**).

```bash
# Windows
mvnw.cmd spring-boot:run
# Linux / Mac / Git Bash
./mvnw spring-boot:run
```

La app queda en **http://localhost:8080**. Al arrancar se crean estos usuarios de prueba:

| Usuario | Contraseña | Roles |
|---|---|---|
| `user@example.com` | `User123!` | USER |
| `admin@example.com` | `Admin123!` | USER, ADMIN |

Direcciones útiles:

| URL | Qué es |
|---|---|
| http://localhost:8080/swagger-ui.html | Documentación interactiva de la API, con botón **Authorize** para el JWT |
| http://localhost:8080/login | Login web: formulario + Google/GitHub (OAuth2) |
| http://localhost:8080/clase17/xss-demo.html | Demo visual de XSS |
| http://localhost:8080/clase17/csrf-demo.html | Demo visual de CSRF |

**Tests automáticos** (31 pruebas que verifican cada concepto):

```bash
./mvnw test
```

**Escaneo de dependencias vulnerables** (OWASP Dependency-Check, Clase 17):

```bash
./mvnw -Powasp verify      # reporte en target/dependency-check-report.html
```

---

## 2. Mapa del proyecto

```
src/main/java/com/app/back/springsecurityaotjwt/
├── clase15_jwt_oauth2/
│   ├── config/      SecurityConfig (las 2 cadenas de filtros), ApplicationConfig, OpenApiConfig (Swagger)
│   ├── jwt/         JwtService (crear/validar tokens), JwtAuthFilter (el "portero" de la API)
│   ├── auth/        AuthController + AuthService (login y registro) + DTOs
│   ├── user/        User (implementa UserDetails), Role, UserRepository, usuarios de prueba
│   ├── oauth2/      OAuth2Controller (login con Google/GitHub)
│   └── demo/        ProtectedApiController (endpoints que exigen JWT)
├── clase16_credenciales_cifrado/
│   ├── config/      PasswordEncoderConfig (BCrypt cost 12 + pepper)
│   ├── password/    PepperedPasswordEncoder, @StrongPassword (validación de fortaleza)
│   ├── hashing/     HashingUtil (SHA-256, sal, integridad con MessageDigest)
│   ├── crypto/      CryptoUtilBasico (ejemplo de la diapositiva), AesGcmEncryptionService, EncryptedStringConverter
│   ├── credenciales/ Guardar tokens de APIs externas CIFRADOS en la base de datos
│   ├── ejercicio/   UsuarioService (Ejercicio N°1: registrar/verificar con BCrypt)
│   └── demo/        CryptoDemoController (endpoints para experimentar)
└── clase17_vulnerabilidades/
    ├── config/      SecurityHeadersConfig (CSP, X-XSS, HSTS...), MethodSecurityConfig (@PreAuthorize)
    ├── csrf/        CsrfDemoController (operación protegida con token CSRF)
    ├── sqlinjection/ Consulta vulnerable vs. parametrizada vs. consulta derivada
    ├── nosql/       Simulación de inyección de operadores MongoDB ($ne, $gt...)
    ├── xss/         Comentarios: validación de entrada y escape de salida
    ├── paginacion/  Bonus: Pageable / PagedModel
    ├── privilegios/ AdminController (mínimo privilegio)
    └── error/       GlobalExceptionHandler (nunca revelar errores internos)

src/main/resources/
├── application.properties       configuración (secretos leídos de variables de entorno)
├── application-prod.properties  perfil de producción: secretos SIN valor por defecto
└── static/clase17/              páginas HTML de las demos de XSS y CSRF
```

---

## 3. Clase 15: Autenticación con JWT y OAuth2

### 3.1 Autenticación vs. autorización

En una API no todo debe estar disponible para cualquiera. Hay que controlar dos cosas distintas:

| Concepto | Pregunta que responde | Si falla, el servidor responde |
|---|---|---|
| **Autenticación** | ¿**Quién** sos? | `401 Unauthorized` |
| **Autorización** | ¿**Qué** podés hacer? | `403 Forbidden` |

### 3.2 ¿Qué es un JWT?

Un **JSON Web Token** es un texto que representa la identidad del usuario. Tiene **tres partes** separadas por puntos:

```
eyJhbGciOiJIUzI1NiJ9 . eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwicm9sZXMiOlsiUk9MRV9VU0VSIl19 . 7p3ZxhBHrtq...
└────── HEADER ─────┘   └──────────────────────── PAYLOAD ───────────────────────────────┘   └─ FIRMA ─┘
 {"alg":"HS256"}         {"sub":"user@example.com","roles":["ROLE_USER"],"exp":...}          HMACSHA256(header.payload, CLAVE)
```

- **Header:** qué algoritmo se usó para firmar.
- **Payload:** los datos (*claims*): usuario (`sub`), roles, fecha de emisión (`iat`) y de vencimiento (`exp`).
- **Firma:** garantiza que nadie modificó el token. Solo quien tiene la **clave secreta** puede generarla.

> ⚠️ **El payload NO está cifrado**, solo codificado en Base64. Cualquiera puede leerlo (probá pegar un token en https://jwt.io). **Nunca** pongas contraseñas ni datos sensibles adentro. La firma impide que lo **modifiquen**, no que lo **lean**.

### 3.3 Flujo típico con JWT

```
 Cliente                                      Servidor (Spring)
   │ 1. POST /api/v1/auth/login {user, pass}     │
   │ ──────────────────────────────────────────► │ 2. valida credenciales y genera un JWT firmado
   │ ◄────────────────────────────────────────── │    {"token": "eyJ..."}
   │ 3. guarda el token                          │
   │ 4. GET /api/test/authenticated              │
   │    Authorization: Bearer eyJ...             │
   │ ──────────────────────────────────────────► │ 5. JwtAuthFilter verifica firma y vencimiento
   │ ◄────────────────────────────────────────── │    200 OK  (o 401 si el token falta / es inválido)
```

El servidor **no guarda** los tokens (es **stateless**): le alcanza con verificar la firma.

### 3.4 Arquitectura de Spring Security

```
Request ─► [Filtros] ─► AuthenticationManager ─► AuthenticationProvider ─┬─► UserDetailsService (busca el usuario en la BD)
              │                                                          └─► PasswordEncoder (compara con el hash, Clase 16)
              ▼
     SecurityContextHolder  (guarda "quién es" el usuario durante la request)
              ▼
         Controller
```

| Pieza | Archivo en el proyecto | Qué hace |
|---|---|---|
| `SecurityFilterChain` | [SecurityConfig.java](src/main/java/com/app/back/springsecurityaotjwt/clase15_jwt_oauth2/config/SecurityConfig.java) | Define qué rutas son públicas y cuáles protegidas |
| `JwtAuthFilter` | [JwtAuthFilter.java](src/main/java/com/app/back/springsecurityaotjwt/clase15_jwt_oauth2/jwt/JwtAuthFilter.java) | Lee el header `Authorization`, valida el JWT y autentica al usuario |
| `JwtService` | [JwtService.java](src/main/java/com/app/back/springsecurityaotjwt/clase15_jwt_oauth2/jwt/JwtService.java) | `generateToken()`, `isTokenValid()`, `extractUsername()` |
| `UserDetails` | [User.java](src/main/java/com/app/back/springsecurityaotjwt/clase15_jwt_oauth2/user/User.java) | El usuario "en el idioma" de Spring (username, password, roles) |
| `AuthenticationManager` | [ApplicationConfig.java](src/main/java/com/app/back/springsecurityaotjwt/clase15_jwt_oauth2/config/ApplicationConfig.java) | Valida usuario + contraseña en el login |
| `AuthService` / `AuthController` | [auth/](src/main/java/com/app/back/springsecurityaotjwt/clase15_jwt_oauth2/auth/) | Endpoints `/register` y `/login` |

### 3.5 Dos cadenas de seguridad en la misma app

| | Cadena 1: API REST (`/api/**`) | Cadena 2: Web (resto) |
|---|---|---|
| Autenticación | JWT en el header `Authorization` | OAuth2 (Google/GitHub) o formulario |
| Estado | **Stateless** (sin sesión) | Con sesión (cookie `JSESSIONID`) |
| CSRF | Deshabilitado (ver Clase 17) | **Habilitado** |

### 3.6 ¿Qué es OAuth2?

Es un **protocolo de autorización** que permite que una aplicación acceda a recursos **en nombre de un usuario sin conocer su contraseña**. Es lo que está detrás de *"Iniciar sesión con Google"*.

1. El usuario elige "Google" en `/login`.
2. Spring lo redirige a Google. El usuario se loguea **en Google** y acepta los permisos.
3. Google vuelve a nuestra app con un **código**; Spring lo cambia por un **access token** y obtiene nombre y email.
4. El usuario queda logueado en nuestra app.

En Spring Boot alcanza con la dependencia `spring-boot-starter-oauth2-client`, el `client-id` / `client-secret` en `application.properties` y `.oauth2Login()` en `SecurityConfig`.

### 3.7 JWT vs. OAuth2

| Característica | JWT | OAuth2 |
|---|---|---|
| Propósito | Autenticación y autorización | Delegación de acceso seguro |
| Portabilidad | Total, se usa en cualquier API | Requiere infraestructura OAuth (proveedor) |
| Token autosuficiente | Sí (contiene los datos del usuario) | No siempre (puede requerir validación externa) |
| Casos comunes | APIs REST, SPAs, microservicios | Login social, apps móviles, APIs de terceros |

> No son excluyentes: OAuth2 muchas veces **usa JWT** como formato de token.

### 3.8 Buenas prácticas

- ✅ **Nunca expongas la clave secreta** que firma los JWT (va en variables de entorno, ver Clase 16).
- ✅ **Usá expiración** (`exp`) en los tokens. Acá: 1 hora (`app.jwt.expiration-ms`).
- ✅ **Validá siempre el token** antes de ejecutar lógica (lo hace `JwtAuthFilter`).
- ✅ **Protegé los endpoints sensibles** (`/admin`, `/usuarios`...). Todo lo que no está en la *white list* exige token.
- ✅ La clave HS256 debe tener **al menos 256 bits** (32 bytes).

---

## 4. Clase 16: Gestión de credenciales y cifrado

### 4.1 Cifrado vs. hashing

```
CIFRADO (reversible, con clave)          HASHING (irreversible, sin clave)
Texto ──[clave]──► XyZ#9 ──[clave]──► Texto      Texto ──[función hash]──► a3f9...c1  (no hay vuelta atrás)
```

| | Cifrado | Hashing |
|---|---|---|
| ¿Se puede revertir? | **Sí**, con la clave | **No** |
| ¿Usa clave? | Sí | No |
| Garantiza | **Confidencialidad** | **Integridad** |
| Tamaño de salida | Proporcional a la entrada | Fijo (SHA-256 = 256 bits) |
| Riesgo principal | Que roben la clave | Algoritmos débiles o rápidos |
| Ejemplos | AES, RSA | SHA-256, BCrypt, Argon2 |

**Regla de oro:** si necesitás **recuperar** el dato → **cifrado**. Si solo necesitás **comprobarlo** → **hash**.

| Dato | Técnica |
|---|---|
| Contraseña de usuario | **Hash** (BCrypt + pepper). Nunca se necesita recuperarla |
| Token de una API externa | **Cifrado** AES (hay que volver a enviarlo) |
| DNI, tarjeta | **Cifrado** AES |
| Verificar que un archivo no cambió | **Hash** SHA-256 |
| Secretos de la app (claves) | **Variables de entorno / Vault** |

### 4.2 Java Cryptography Architecture (JCA)

| Clase | Para qué | Dónde se usa en el proyecto |
|---|---|---|
| `MessageDigest` | Crear hashes (SHA-256) | [HashingUtil.java](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/hashing/HashingUtil.java) |
| `Cipher` | Cifrar y descifrar | [AesGcmEncryptionService.java](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/crypto/AesGcmEncryptionService.java) |
| `KeyGenerator` | Generar claves secretas | `AesGcmEncryptionService.generateNewBase64Key()` |
| `SecretKey` / `SecretKeySpec` | Representar una clave | idem |
| `SecureRandom` | Números aleatorios seguros (sal, IV) | `HashingUtil.generateSalt()` |

### 4.3 Sal y pepper

| | Sal (salt) | Pimienta (pepper) |
|---|---|---|
| Qué es | Valor **aleatorio** distinto por contraseña | Valor **secreto** igual para todas |
| Dónde se guarda | Junto al hash (no es secreta) | **Fuera** de la base de datos (variable de entorno) |
| Qué evita | Que dos contraseñas iguales tengan el mismo hash; *rainbow tables* | Que un robo de la BD sirva de algo sin el pepper |
| En el proyecto | BCrypt la agrega solo | [PepperedPasswordEncoder.java](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/password/PepperedPasswordEncoder.java) |

### 4.4 SHA-256 vs. BCrypt para contraseñas

| Característica | SHA-256 | BCrypt |
|---|---|---|
| Tipo | Hash criptográfico | Derivador de clave (para contraseñas) |
| Sal incorporada | ❌ (manual) | ✅ Automática |
| Cost factor ajustable | ❌ | ✅ (2^cost iteraciones) |
| Velocidad | Muy rápida | **Intencionalmente lenta** |
| Resistencia a fuerza bruta | Baja para contraseñas | Alta |
| Uso ideal | Integridad de datos, firmas | Contraseñas |

**¿Por qué "lento" es bueno?** Una GPU calcula miles de millones de SHA-256 por segundo: un atacante prueba diccionarios enteros en minutos. Con BCrypt cost 12 (2^12 = 4096 iteraciones) cada intento tarda ~0,25 s. Para un usuario no se nota; para un atacante es un muro.

Anatomía de un hash BCrypt:

```
$2a$12$7v1xRp1XGHqrlqvhz3S4HuF.zv9PRAwOB8yWliZ08VvKnkhUd3X4a
 │   │  └──── sal (22 car.) ────┘└──────── hash (31 car.) ───┘
 │   └─ cost factor (12 → 4096 iteraciones)
 └─ versión del algoritmo
```

En el proyecto, toda la app usa BCrypt cost 12 + pepper: [PasswordEncoderConfig.java](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/config/PasswordEncoderConfig.java).

```java
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode("password123");              // al registrar
boolean ok  = encoder.matches("password123", hash);        // al hacer login
```

> ⚠️ No se compara con `encode(password).equals(hash)`: cada `encode` usa una sal distinta. `matches()` saca la sal del hash guardado y repite el cálculo.

### 4.5 AES: del ejemplo básico a la versión correcta

La diapositiva muestra `Cipher.getInstance("AES")` con la clave en el código. Está en [CryptoUtilBasico.java](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/crypto/CryptoUtilBasico.java) **solo para aprender**. Tiene tres problemas:

| Problema | Consecuencia | Solución ([AesGcmEncryptionService](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/crypto/AesGcmEncryptionService.java)) |
|---|---|---|
| Clave hardcodeada | Quien vea el código descifra todo | Clave en variable de entorno `AES_KEY` |
| `"AES"` = modo **ECB** | Mismo texto → mismo cifrado (filtra patrones) | `AES/GCM/NoPadding` con **IV aleatorio** |
| Sin autenticación | Un dato alterado se descifra como basura sin aviso | GCM detecta la manipulación y lanza error |

Además, [EncryptedStringConverter](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/crypto/EncryptedStringConverter.java) cifra **automáticamente** una columna de la BD con `@Convert`. Ejemplo: [CredencialExterna](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/credenciales/CredencialExterna.java).

### 4.6 Almacenamiento seguro de secretos

- ❌ **Nunca** escribas claves en el código fuente ni las subas a Git.
- ✅ Leelas de **variables de entorno** o de un **Vault** (HashiCorp Vault, AWS Secrets Manager...).
- ✅ En este proyecto: `application.properties` usa `${JWT_SECRET:valorDeDesarrollo}` y el perfil `prod` usa `${JWT_SECRET}` **sin** valor por defecto: si falta, la app no arranca.
- ✅ `.env` está en `.gitignore`; se sube solo [.env.example](.env.example) (sin valores).
- ✅ **Rotá** las claves periódicamente y separá los secretos de desarrollo y producción.

### 4.7 Errores comunes y soluciones

| Error común | Solución |
|---|---|
| Guardar contraseñas en texto plano | Hashear con BCrypt (o Argon2) |
| Hardcodear claves en el código | Variables de entorno, `.env`, Vault |
| No agregar sal | Algoritmos con sal automática (BCrypt) |
| Usar MD5 o SHA-1 | Están rotos: SHA-256 para integridad, BCrypt para contraseñas |
| Subir secretos a Git | `.gitignore` + escaneo de secretos |
| No validar la longitud ni la complejidad | `@StrongPassword` ([StrongPasswordValidator](src/main/java/com/app/back/springsecurityaotjwt/clase16_credenciales_cifrado/password/StrongPasswordValidator.java)) |

---

## 5. Clase 17: Prevención de vulnerabilidades

Las aplicaciones web están expuestas sobre todo cuando **reciben datos del usuario**. Las tres vulnerabilidades más comunes:

| Ataque | En una frase | Defensa principal |
|---|---|---|
| **CSRF** | Otro sitio usa tu sesión abierta para hacer acciones en tu nombre | Token CSRF |
| **SQL / NoSQL Injection** | El atacante escribe código de consulta dentro de un campo de texto | Consultas parametrizadas / derivadas |
| **XSS** | El atacante inyecta JavaScript que se ejecuta en el navegador de otros usuarios | Escapar la salida + CSP |

### 5.1 CSRF (Cross-Site Request Forgery)

**El ataque:** estás logueado en tu banco (el navegador tiene la cookie de sesión). Entrás a un sitio malicioso que envía en secreto un formulario a `tubanco.com/transferencias`. El navegador **agrega sola** tu cookie, y el banco cree que fuiste vos.

**La defensa:** un **token CSRF** secreto que la página legítima reenvía en cada operación. El sitio malicioso no puede leerlo, así que su petición llega sin token y Spring responde **403**.

| Tipo de aplicación | Qué hacer |
|---|---|
| API REST pura con JWT en el header | CSRF **deshabilitado** (`csrf.disable()`). El navegador no agrega el header `Authorization` solo. JWT nunca en cookies + HTTPS |
| Aplicación web con sesión/cookies | CSRF **habilitado** + cookies `SameSite` + doble envío (cookie + header) |

| Repositorio de tokens | Uso típico |
|---|---|
| `.disable()` | APIs stateless (JWT en headers) |
| `HttpSessionCsrfTokenRepository` | Apps con sesión server-side (Spring MVC clásico). Es el default |
| `CookieCsrfTokenRepository.withHttpOnlyFalse()` | SPAs (React/Angular) que leen el token de la cookie `XSRF-TOKEN` y lo mandan en `X-XSRF-TOKEN` |

En el proyecto: la cadena `/api/**` tiene CSRF deshabilitado y la cadena web lo tiene habilitado con `CookieCsrfTokenRepository` ([SecurityConfig](src/main/java/com/app/back/springsecurityaotjwt/clase15_jwt_oauth2/config/SecurityConfig.java), [CsrfDemoController](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/csrf/CsrfDemoController.java)). Además, **nunca** modifiques datos con `GET`.

### 5.2 SQL Injection

```java
// ❌ VULNERABLE: concatena lo que escribió el usuario
String sql = "SELECT * FROM productos WHERE nombre = '" + nombre + "'";
// nombre = x' OR '1'='1   →   ... WHERE nombre = 'x' OR '1'='1'   → ¡devuelve TODO!

// ✅ SEGURO: consulta parametrizada (el ? es siempre un DATO, nunca código)
jdbcTemplate.queryForList("SELECT * FROM productos WHERE nombre = ?", nombre);

// ✅ SEGURO: consulta derivada de Spring Data
List<Producto> findByVisibleTrueAndNombre(String nombre);
```

Archivos: [SqlInjectionDemoService](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/sqlinjection/SqlInjectionDemoService.java), [ProductoRepository](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/sqlinjection/ProductoRepository.java). La demo incluye un ataque `UNION` que lee la tabla de usuarios: ahí se ve por qué las contraseñas deben estar hasheadas (Clase 16).

### 5.3 NoSQL Injection (MongoDB / Firestore)

En MongoDB las consultas son JSON. Si se acepta un **objeto** donde se espera un **texto**, se pueden inyectar operadores:

```java
@Query("{ 'username' : ?0, 'password' : ?1 }")      // ❌ con entradas sin validar
// El atacante envía: { "username": {"$ne": null}, "password": {"$ne": null} }
// = "cualquier usuario con username y password no nulos" → ¡entra sin contraseña!

User findByUsernameAndPassword(String u, String p);  // ✅ consulta derivada: valores literales
```

| Operador | Significado | Ejemplo |
|---|---|---|
| `$ne` | Distinto de | `{ "role": { "$ne": "admin" } }` |
| `$gt` / `$lt` | Mayor / menor que | `{ "edad": { "$gt": 18 } }` |
| `$or` | Cualquiera de las condiciones | `{ "$or": [ {...}, {...} ] }` |
| `$regex` | Expresión regular | `{ "email": { "$regex": ".*@gmail.com" } }` |

| Estrategia | ¿Segura? |
|---|---|
| Consulta derivada por nombre de método | ✅ Sí, la preferida |
| `@Query` con parámetros | ⚠️ Parcialmente: depende de validar las entradas |
| Query armada a mano con objetos JSON | ❌ Riesgo alto |

En el proyecto ([NoSqlInjectionDemoController](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/nosql/NoSqlInjectionDemoController.java)) se **simula** Mongo en memoria: el endpoint que recibe un `Map` es vulnerable; el que recibe un DTO con `String` rechaza el ataque con **400**. También está el ejemplo de Firestore: validar IDs con `^[a-zA-Z0-9_-]{3,30}$` antes de usarlos.

### 5.4 XSS (Cross-Site Scripting)

**El ataque en una API REST:**

1. El atacante publica el comentario `<img src=x onerror="alert('XSS')">`.
2. La API lo guarda y lo devuelve tal cual en el JSON.
3. El frontend hace `div.innerHTML = comentario.texto`.
4. El navegador **ejecuta** el script en la sesión de cada persona que ve la página.

**Defensa en capas** (ninguna sola alcanza):

| Capa | Cómo | Dónde |
|---|---|---|
| Validar la entrada | `@Valid` + DTO con `@NotBlank`, `@Size`, `@Email` | todos los DTOs |
| Escapar la salida | `HtmlUtils.htmlEscape()` → `<` se convierte en `&lt;` | [ComentarioController](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/xss/ComentarioController.java) |
| Frontend seguro | `textContent` en vez de `innerHTML` (React/Angular escapan por defecto) | [xss-demo.js](src/main/resources/static/clase17/xss-demo.js) |
| Content-Security-Policy | El navegador se niega a ejecutar scripts inline | [SecurityHeadersConfig](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/config/SecurityHeadersConfig.java) |

Si necesitás permitir **algo** de HTML (negritas, links), usá una librería como **OWASP Java HTML Sanitizer** con una lista blanca de etiquetas.

### 5.5 Headers de seguridad (Spring Security)

| Header | Función |
|---|---|
| `Content-Security-Policy` | Limita de dónde se cargan scripts, estilos, etc. Es la defensa más fuerte contra XSS |
| `X-XSS-Protection: 1; mode=block` | Pide bloquear la página si se detecta XSS. Los navegadores modernos ya lo ignoran; se envía por compatibilidad |
| `X-Frame-Options: DENY` | Impide meter la página en un `<iframe>` (*clickjacking*) |
| `Strict-Transport-Security` | Obliga a usar HTTPS (solo se envía en conexiones HTTPS) |
| `X-Content-Type-Options: nosniff` | El navegador no "adivina" tipos de archivo |

### 5.6 Bonus: paginación

`findAll()` sobre un millón de registros = memoria agotada, respuesta lenta y BD sobrecargada. Con `Pageable` se piden páginas:

```java
Page<Producto> findByVisibleTrueAndCategoria(String categoria, Pageable pageable);
// GET /api/clase17/productos?categoria=accesorios&page=0&size=10&sort=precio,desc
// totalPaginas = totalElementos / tamañoPagina  → 30 / 10 = 3
```

En [ProductoPaginadoController](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/paginacion/ProductoPaginadoController.java) además se **limita el tamaño máximo** (50) para que nadie pida `size=1000000`.

### 5.7 OWASP Dependency-Check y otras herramientas

Tu código puede ser perfecto y aun así ser vulnerable por una **librería** con fallas conocidas (CVE). El plugin `dependency-check-maven` compara tus dependencias con la base NVD:

```bash
./mvnw -Powasp verify
# Reporte: target/dependency-check-report.html
# CVSS >= 9.0 crítica (rojo) · 7.0-8.9 alta (naranja) · < 7.0 media/baja (amarillo)
```

Complementos: **OWASP ZAP** (escáner de la app en ejecución), **SonarQube** (análisis estático), **Spring Boot Actuator** + auditoría de Spring Security.

### 5.8 Principios de seguridad web

| Principio | Dónde se ve en el proyecto |
|---|---|
| Validación del lado del servidor | `@Valid` en todos los controllers |
| Mínimo privilegio | `@EnableMethodSecurity` + `@PreAuthorize("hasRole('ADMIN')")` en [AdminController](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/privilegios/AdminController.java) |
| Tokens únicos por sesión | Token CSRF de la cadena web |
| No confiar nunca en el frontend | Toda validación se repite en el backend |
| Nunca revelar errores del backend | [GlobalExceptionHandler](src/main/java/com/app/back/springsecurityaotjwt/clase17_vulnerabilidades/error/GlobalExceptionHandler.java) + `spring.web.error.include-stacktrace=never` |

---

## 6. Glosario rápido

| Término | Significado |
|---|---|
| **Bearer token** | "Token al portador": quien lo tiene, accede. Se envía como `Authorization: Bearer <token>` |
| **Claim** | Cada dato dentro del payload de un JWT (`sub`, `exp`, `roles`...) |
| **Stateless** | El servidor no guarda estado (sesión) entre requests |
| **Filtro** | Código que se ejecuta antes de que la request llegue al controller |
| **SecurityContext** | Lugar donde Spring guarda quién es el usuario autenticado en la request actual |
| **Hash** | Huella digital irreversible de un dato |
| **Sal / Pepper** | Valor aleatorio (público) / secreto (fuera de la BD) que fortalece un hash |
| **Cost factor** | Cuántas veces (2^cost) se repite BCrypt |
| **IV** | Vector de inicialización: valor aleatorio que hace que el mismo texto cifre distinto |
| **CVE / CVSS** | Identificador de una vulnerabilidad pública / puntaje de gravedad (0 a 10) |
| **401 vs 403** | "No sé quién sos" vs. "sé quién sos, pero no tenés permiso" |

> **Nota sobre Spring Boot 4 / Spring Security 7:** al loguearte por formulario, `/profile` muestra además la autoridad `FACTOR_PASSWORD`. Spring Security 7 la agrega para registrar **con qué factor** te autenticaste (base del soporte de autenticación multifactor). No es un rol.
