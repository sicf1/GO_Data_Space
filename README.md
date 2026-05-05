# Sprout - Data Space Seguro en Go

Este proyecto implementa una version funcional de la practica de `Seguridad y Confidencialidad`: un `data space` sanitario reducido con servidor HTTPS, base de datos cifrada y clientes de terminal por entidad.

## Ejecucion

1. Lanza la aplicacion:
   ```bash
   go run main.go
   ```
2. Selecciona la entidad cliente:
   - `hospital1`
   - `hospital2`
   - `hospital3`
   - `centro de investigacion1`
3. Introduce la clave maestra de la entidad seleccionada.
4. Introduce la clave maestra del servidor compartido.
5. En el primer arranque se solicitara crear el administrador inicial.

## Cambios principales

- Cada paciente recibe un seudonimo estable `id1`, `id2`, `id3`, ... segun su orden de creacion.
- Los registros anonimizados que llegan al servidor usan `patientId` en lugar del nombre real del paciente.
- Cada entidad cliente guarda su informacion local en una ruta propia:
  - `data/clients/hospital1`
  - `data/clients/hospital2`
  - `data/clients/hospital3`
  - `data/clients/centro_investigacion1`
- El servidor compartido guarda su informacion en `data/server`.

## Funcionalidades Data Space

- Armonizacion de datos de salud en un formato XML local.
- Anonimizacion antes de subir registros al servidor.
- Almacenamiento local cifrado de datos no anonimizados por entidad.
- Almacenamiento servidor cifrado de registros anonimizados.
- Estadisticas agregadas por clasificacion y rango de edad para consultas autorizadas.

## Menus por rol

- Administrador:
  - autorizar o denegar peticiones de consulta
  - dar de alta medico
  - dar de alta investigador
  - dar de alta paciente
- Paciente:
  - revocar permisos de uso de datos
  - restablecer permisos de uso de datos
- Medico:
  - introducir datos de paciente
  - listar registros locales
  - subir registro anonimizado
- Investigador:
  - hacer peticion de consulta de datos
  - ver consultas aprobadas
  - ver consultas denegadas

## Medidas de seguridad

- Autentificacion segura mediante contraseñas con `Argon2id` y sal aleatoria por usuario.
- Compresion y cifrado de la base de datos con `gzip + AES-256-GCM`.
- Gestion de claves maestras fuera del codigo.
- Comunicacion segura cliente-servidor mediante `HTTPS` con certificado autofirmado para `localhost`.
- Sesiones seguras con token aleatorio y expiracion por inactividad.

## Estructura principal

- `main.go`: seleccion de entidad, lectura de claves maestras y arranque conjunto.
- `pkg/api`: tipos compartidos, roles, registros y peticiones de consulta.
- `pkg/client`: perfiles de entidad, menus por rol, almacenamiento local seguro y cliente HTTPS.
- `pkg/server`: HTTPS, autenticacion, autorizacion, consentimiento, migracion de IDs y estadisticas.
- `pkg/store`: `bbolt` y decorador de cifrado/compresion.
- `scripts/inspect_db.go`: inspeccion de la base de datos del servidor o de una entidad cliente.

## Validacion

```bash
go test ./...
```

La suite cubre almacenamiento cifrado, clave maestra incorrecta, flujo completo por roles, expiracion de sesion, robustez JSON y migracion de pacientes legacy a `idN`.
