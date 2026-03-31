# Sprout - Data Space Seguro en Go

Este proyecto implementa una versión funcional de la práctica de `Seguridad y Confidencialidad`: un `data space` sanitario reducido con cliente de terminal, servidor HTTPS, base de datos cifrada y control de acceso por roles.

## Ejecución

1. Lanza la aplicación:
   ```bash
   go run main.go
   ```
2. Introduce la contraseña maestra de cifrado.
3. En el primer arranque se solicitará crear el administrador inicial.
4. Desde el menú del administrador se podrán dar de alta médicos, investigadores y pacientes.

## Funcionalidades Data Space

- ✅ Mecanismo para armonizar datos de salud en un formato XML propio y sencillo.
- ✅ Mecanismo para anonimizar los datos antes de subirlos al servidor.
- ✅ El cliente almacena localmente los datos armonizados sin anonimizar.
- ✅ El servidor almacena los registros anonimizados y protegidos.
- ✅ El servidor devuelve estadísticas agregadas por clasificación y rango de edad para consultas autorizadas.

### Menús por rol

- ✅ Administrador:
  - autorizar o denegar peticiones de consulta
  - dar de alta médico
  - dar de alta investigador
  - dar de alta paciente
- ✅ Paciente:
  - revocar permisos de uso de datos
  - restablecer permisos de uso de datos
- ✅ Médico:
  - introducir datos de paciente
  - listar registros locales
  - subir registro anonimizado
- ✅ Investigador:
  - hacer petición de consulta de datos
  - ver consultas aprobadas
  - ver consultas denegadas

## Medidas de seguridad

- ✅ Autentificación segura mediante contraseñas con `Argon2id` y sal aleatoria por usuario.
- ✅ Compresión y cifrado de la base de datos con `gzip + AES-256-GCM`.
- ✅ Gestión de la clave maestra fuera del código, solicitándola al arrancar y derivando la clave con `Argon2id`.
- ✅ Comunicación segura cliente-servidor mediante `HTTPS` con certificado autofirmado para `localhost`.
- ✅ Sesiones seguras con token aleatorio y expiración por inactividad.

## Estado de extras

- <span style="color:red">Extra</span> ✅ Expiración de sesiones por inactividad.
- <span style="color:red">Extra</span> ✅ Flujo de aprobación de consultas para investigadores.
- <span style="color:red">Extra</span> ✅ Revocación dinámica del uso de datos por parte del paciente.

## Estructura principal

- `main.go`: arranque, contraseña maestra y bootstrap del administrador inicial.
- `pkg/api`: tipos compartidos, roles, registros y peticiones de consulta.
- `pkg/client`: menús por rol, almacenamiento local seguro y cliente HTTPS.
- `pkg/server`: HTTPS, autenticación, autorización, consentimiento y estadísticas.
- `pkg/store`: `bbolt` y decorador de cifrado/compresión.

## Validación

- Tests:
  ```bash
  go test ./...
  ```
- La suite actual cubre:
  - roundtrip y protección del `SecureStore`
  - detección de clave maestra incorrecta
  - flujo completo administrador/médico/investigador/paciente
  - expiración de sesión
  - robustez básica del endpoint JSON
