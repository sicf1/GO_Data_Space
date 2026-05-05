# Guia de Presentacion del Proyecto Sprout

## 1. Idea general

`Sprout` es un `data space` sanitario reducido implementado en Go.

La idea del proyecto es separar claramente:

- Los datos clinicos completos, que se guardan solo en el cliente local del medico.
- Los datos anonimizados, que son los unicos que se suben al servidor.
- Las consultas agregadas, que solo pueden verse si han sido solicitadas por un investigador y aprobadas por un administrador.

El sistema junta en una sola aplicacion:

- Un cliente de terminal.
- Un servidor HTTPS local.
- Persistencia en base de datos.
- Cifrado de almacenamiento.
- Autenticacion y autorizacion por roles.

## 2. Objetivo academico

El proyecto demuestra varios conceptos de la asignatura:

- Proteccion de confidencialidad.
- Control de acceso por roles.
- Separacion entre dato identificable y dato anonimo.
- Cifrado de datos en reposo.
- Comunicacion segura cliente-servidor.
- Sesiones seguras.
- Validacion de entradas y flujos.

En otras palabras: no es solo una app CRUD, sino una practica de seguridad aplicada a un caso sanitario.

## 3. Que problema resuelve

En un entorno sanitario no todo el mundo debe ver lo mismo:

- El medico necesita trabajar con el dato completo del paciente.
- El investigador no debe ver datos personales, solo estadisticas agregadas.
- El paciente debe poder revocar el uso de sus datos.
- El administrador controla el alta de usuarios y la aprobacion de consultas.

Por eso el sistema implementa un flujo con cuatro roles:

- `admin`
- `doctor`
- `researcher`
- `patient`

## 4. Arquitectura

La arquitectura principal es:

- `main.go`: arranque, lectura de contraseña maestra, bootstrap del admin y lanzamiento conjunto de servidor y cliente.
- `pkg/client`: menus por rol, cliente HTTPS y almacenamiento local del medico.
- `pkg/server`: API JSON por HTTPS, autenticacion, autorizacion, sesiones, consentimiento y estadisticas.
- `pkg/api`: tipos compartidos entre cliente y servidor.
- `pkg/store`: abstraccion de persistencia con `bbolt` y una capa adicional de cifrado/compresion.
- `pkg/ui`: utilidades de terminal.

### Flujo de alto nivel

1. Se arranca la aplicacion con `go run main.go`.
2. El usuario introduce una contraseña maestra.
3. Esa contraseña deriva la clave que protege la base de datos.
4. Si no existe administrador inicial, se crea.
5. Se levanta el servidor HTTPS local.
6. El cliente de terminal se conecta a `https://localhost:8443/api`.

## 5. Modelo de datos

El proyecto distingue dos formatos de registro:

### `LocalRecord`

Es el registro armonizado completo que se guarda en local.

Contiene:

- `ID`
- `Classification`
- `AgeRange`
- `Sex`
- `PatientUsername`
- `PatientAlias`
- `Observation`
- `CreatedAt`
- `UploadedBy`

Puntos clave:

- Se guarda en XML.
- Conserva `PatientAlias` y `Observation`, que son datos sensibles.
- Solo vive en la base de datos local del cliente.

### `AnonymizedRecord`

Es la version que se sube al servidor.

Contiene:

- `ID`
- `Classification`
- `AgeRange`
- `Sex`
- `PatientUsername`
- `CreatedAt`
- `UploadedBy`

Puntos clave:

- Ya no incluye `PatientAlias`.
- Ya no incluye `Observation`.
- El servidor no almacena el detalle clinico completo.

## 6. Armonizacion y validacion

Antes de guardar o subir datos, el sistema armoniza los campos a un conjunto controlado.

### Clasificaciones admitidas

- `consulta`
- `urgencia`
- `hospitalizacion`
- `analitica`
- `imagen`

### Valores de sexo admitidos

- `M`
- `F`
- `X`
- `ND`

### Rangos de edad

- `0-17`
- `18-35`
- `36-50`
- `51-65`
- `66+`

La edad original no se sube: se transforma a un rango para reducir identificabilidad.

## 7. Roles y permisos

### Administrador

Puede:

- Dar de alta medicos.
- Dar de alta investigadores.
- Dar de alta pacientes.
- Aprobar o denegar peticiones de consulta.

No se permite crear administradores desde el menu normal.
El administrador inicial se crea solo en el primer arranque.

### Medico

Puede:

- Introducir datos de paciente.
- Guardar registros completos en local.
- Listar registros locales.
- Subir versiones anonimizadas al servidor.

Ademas, ahora el cliente valida que el usuario del paciente exista antes de guardar un registro local, para evitar inconsistencias.

### Investigador

Puede:

- Solicitar una consulta estadistica.
- Ver consultas aprobadas.
- Ver consultas denegadas.

No puede ver datos clinicos completos ni subir registros.

### Paciente

Puede:

- Revocar permisos de uso de datos.
- Restablecer permisos de uso de datos.

Cuando revoca, sus datos dejan de contarse en las estadisticas agregadas.

## 8. Seguridad implementada

Esta es una de las partes mas importantes para explicar al profesor.

### 8.1. Contraseñas de usuarios

Las contraseñas de los usuarios no se guardan en claro.

Se usa:

- `Argon2id`
- Sal aleatoria por usuario

Esto protege frente a robo de hashes y ataques de diccionario mucho mejor que guardar texto plano o usar hashes simples.

### 8.2. Contraseña maestra

Al arrancar, la aplicacion pide una contraseña maestra.

Esa contraseña:

- No esta hardcodeada.
- Se usa para derivar una clave de 32 bytes.
- Protege tanto la base de datos del servidor como la local del cliente.

La derivacion tambien usa `Argon2id` con una sal persistente.

### 8.3. Cifrado en reposo

La persistencia real usa `bbolt`, pero encima hay una capa `SecureStore`.

`SecureStore` hace:

1. Compresion con `gzip`
2. Cifrado con `AES-256-GCM`
3. Almacenamiento del resultado en `bbolt`

Ventajas:

- El contenido sensible no queda en claro en el fichero.
- `AES-GCM` aporta confidencialidad e integridad.
- La compresion reduce tamaño y unifica el formato antes del cifrado.

### 8.4. Verificacion de clave maestra correcta

El sistema guarda un valor centinela cifrado.

Al abrir la base de datos:

- Si se puede descifrar correctamente, la clave maestra es valida.
- Si no, se devuelve error de clave maestra incorrecta.

Esto evita trabajar con una contraseña maestra incorrecta como si fuera correcta.

### 8.5. Comunicacion segura

Cliente y servidor se comunican por:

- `HTTPS`
- Certificado autofirmado para `localhost`

El certificado se genera automaticamente si no existe.
El cliente confia explicitamente en ese certificado local.

### 8.6. Sesiones

Las sesiones usan:

- Token aleatorio generado con `crypto/rand`
- Expiracion por inactividad

Esto evita tener que reenviar credenciales en cada operacion y mejora la seguridad de sesion.

## 9. Flujo funcional completo

Este es el flujo que mejor conviene enseñar en una demo.

### Primer arranque

1. Ejecutar `go run main.go`
2. Introducir contraseña maestra
3. Crear administrador inicial

### Alta de usuarios

Con el administrador:

- Crear un medico
- Crear un investigador
- Crear un paciente

### Trabajo del medico

1. Iniciar sesion como medico
2. Introducir datos de paciente
3. El cliente valida que el paciente exista
4. Se armoniza el registro
5. Se guarda en local como XML
6. Se sube una version anonimizada al servidor

### Trabajo del investigador

1. Iniciar sesion como investigador
2. Solicitar consulta por clasificacion o rango de edad
3. Queda en estado `pending`

### Trabajo del administrador

1. Ver peticiones pendientes
2. Aprobar o denegar

### Trabajo del investigador tras aprobacion

1. Ver consultas aprobadas
2. Obtener estadisticas agregadas

### Trabajo del paciente

1. Iniciar sesion como paciente
2. Revocar permiso de uso de datos
3. Volver a consultar como investigador
4. Observar que esos datos dejan de contarse

## 10. Como demostrar que hay anonimización real

Este punto suele ser importante en una defensa.

Puedes explicar que el sistema no solo "dice" que anonimiza, sino que:

- El medico trabaja con un `LocalRecord` mas rico.
- El servidor solo recibe `AnonymizedRecord`.
- Campos sensibles como alias y observaciones no salen del cliente.
- Las consultas del investigador devuelven conteos agregados, no registros individuales.

Eso implementa minimizacion de datos: cada actor ve solo lo necesario.

## 11. Como demostrar que hay control de acceso real

Puedes resumirlo asi:

- El medico puede subir registros, pero no aprobar consultas.
- El investigador puede pedir estadisticas, pero no ver detalle clinico.
- El paciente puede revocar consentimiento, pero no crear usuarios.
- El administrador puede autorizar consultas y altas, pero no se crea desde el flujo normal.

El servidor comprueba el rol en cada accion, no solo el cliente.
Eso es importante: la seguridad esta en backend, no solo en la interfaz.

## 12. Persistencia y ficheros creados

En el primer uso se crean archivos en `data/`:

- `data/server.db`
- `data/master.salt`
- `data/tls/server.crt`
- `data/tls/server.key`
- `data/client.db`
- `data/client.salt`

Interpretacion:

- `server.db`: base de datos del servidor
- `client.db`: base de datos local del cliente
- `master.salt` y `client.salt`: sales para derivacion de claves
- `server.crt` y `server.key`: material TLS local

## 13. Pruebas implementadas

La validacion automatica se ejecuta con:

```bash
go test ./...
```

La suite cubre:

- Correcto cifrado y descifrado de `SecureStore`
- Deteccion de clave maestra incorrecta
- Persistencia basica de `bbolt`
- Flujo completo de administrador, medico, investigador y paciente
- Expiracion de sesion
- Rechazo de JSON con campos desconocidos
- Rechazo de JSON con basura al final
- Validacion de existencia del paciente antes del flujo medico

Esto es importante para decir que el proyecto no solo funciona "a mano", sino que parte del comportamiento esta verificado por tests.

## 14. Decisiones de diseño que merece la pena defender

### Cliente terminal en vez de web

Ventaja:

- Reduce complejidad y centra el trabajo en seguridad, modelo de datos y control de acceso.

### XML local y JSON en API

Ventaja:

- XML sirve como formato armonizado propio para el almacenamiento local.
- JSON simplifica la comunicacion cliente-servidor.

### `bbolt` como base de datos

Ventaja:

- Es ligera, embebida y suficiente para una practica local.
- Evita depender de un servidor de base de datos externo.

### Cifrar los valores de la store

Ventaja:

- Permite reutilizar la misma abstraccion `Store`.
- Se desacopla la logica de negocio de la estrategia de proteccion.

### Aprobacion administrativa de consultas

Ventaja:

- Introduce una capa real de gobernanza del dato.
- Tiene sentido en un data space sanitario.

## 15. Limitaciones conocidas

Conviene reconocerlas si te preguntan. Eso suele dar buena imagen.

- Es una aplicacion local para demostracion, no un despliegue distribuido real.
- El certificado TLS es autofirmado y pensado para `localhost`.
- El servidor devuelve estadisticas agregadas simples, no analitica avanzada.
- No hay interfaz grafica; la interaccion es por terminal.
- Los metadatos estructurales de `bbolt` no se ocultan por completo, aunque los valores si van protegidos.
- El sistema usa una unica contraseña maestra para este escenario integrado cliente-servidor.

## 16. Preguntas

### "Donde esta la anonimización?"

En la transformacion de `LocalRecord` a `AnonymizedRecord`: el servidor no recibe alias ni observaciones, y el investigador solo ve agregados.

### "Como se protege la base de datos?"

Con `SecureStore`, que comprime con `gzip` y cifra con `AES-256-GCM` antes de guardar en `bbolt`.

### "Como se almacenan las contraseñas?"

Con `Argon2id` y sal aleatoria por usuario. No se guardan en claro.

### "Como se protege la comunicacion?"

Con HTTPS local y certificado autofirmado generado automaticamente para `localhost`.

### "Como se impide que cualquiera haga consultas?"

Por roles, autenticacion por token de sesion y aprobacion administrativa de solicitudes.

### "Que pasa si el paciente retira el consentimiento?"

Sus datos dejan de entrar en el calculo de estadisticas cuando el investigador consulta resultados aprobados.

### "Que extras tiene el proyecto?"

- Expiracion de sesiones por inactividad
- Flujo de aprobacion de consultas
- Revocacion dinamica del uso de datos por parte del paciente

## 17. Guion corto de presentacion oral

Puedes decir algo como esto:

> Este proyecto implementa un data space sanitario reducido en Go. La idea principal es separar el dato clinico completo, que solo se guarda en local en el cliente del medico, del dato anonimizado, que es lo unico que llega al servidor. El sistema tiene cuatro roles: administrador, medico, investigador y paciente. Hemos protegido las contraseñas con Argon2id, la persistencia con AES-256-GCM sobre bbolt, y la comunicacion con HTTPS local. Ademas, las consultas del investigador no son libres: primero se solicitan, luego el administrador las aprueba o deniega, y finalmente el paciente puede revocar el consentimiento para que sus datos no se utilicen. Con esto demostramos confidencialidad, control de acceso, minimizacion de datos y seguridad en reposo y en transito.

## 18. Orden recomendado para la demo

1. Explicar el objetivo en 20 segundos.
2. Lanzar `go run main.go`.
3. Enseñar el primer arranque y la contraseña maestra.
4. Crear admin, medico, investigador y paciente.
5. Como medico, crear y subir un registro.
6. Como investigador, pedir una consulta.
7. Como admin, aprobarla.
8. Como investigador, mostrar estadisticas.
9. Como paciente, revocar consentimiento.
10. Volver al investigador y enseñar el cambio.

## 19. Mensaje final para cerrar la presentacion

La fortaleza del proyecto no esta solo en que "funciona", sino en que aplica principios de seguridad de forma coherente:

- minimiza datos
- separa responsabilidades
- cifra persistencia
- protege credenciales
- usa TLS
- controla sesiones
- obliga a pasar por autorizacion y consentimiento

Ese es el valor principal que conviene transmitir.
