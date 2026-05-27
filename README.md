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
5. La primera vez que entres con una entidad se solicitara crear el administrador de esa organizacion.

## Cambios principales

- Cada paciente recibe un seudonimo estable `id1`, `id2`, `id3`, ... segun su orden de creacion.
- Los registros anonimizados que llegan al servidor usan `patientId` en lugar del nombre real del paciente.
- Cada usuario queda ligado a una organizacion:
  - `hospital1`
  - `hospital2`
  - `hospital3`
  - `centro_investigacion1`
- Cada organizacion tiene su propio administrador y ese admin solo puede iniciar sesion y actuar dentro de su organizacion.
- El `centro de investigacion1` no puede consultar un hospital sin antes conseguir un acuerdo aprobado con ese hospital.
- Cada consulta de investigacion apunta a un unico hospital y las estadisticas se calculan solo sobre ese hospital.
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
- Flujo de acuerdos hospital-centro antes de permitir consultas de investigacion.
- Estadisticas agregadas por clasificacion y rango de edad para consultas autorizadas.

## Menus por rol

- Administrador:
  - en hospital: revisar acuerdos, autorizar consultas, dar de alta medico y paciente
  - en centro: dar de alta investigador y consultar acuerdos
- Paciente:
  - revocar permisos de uso de datos
  - restablecer permisos de uso de datos
- Medico:
  - introducir datos de paciente
  - listar registros locales
  - subir registro anonimizado
- Investigador:
  - solicitar acuerdo con hospital
  - ver acuerdos
  - hacer peticion de consulta de datos para un hospital concreto
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

La suite cubre almacenamiento cifrado, clave maestra incorrecta, flujo completo hospital-centro con acuerdos, expiracion de sesion, robustez JSON y migracion de pacientes legacy a `idN`.
