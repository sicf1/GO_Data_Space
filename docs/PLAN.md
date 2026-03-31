# Plan de implementación sobre la base actual de `sprout`

## Resumen
Partiremos de la arquitectura existente cliente terminal + servidor HTTP + `store` abstracción, y la convertiremos en un sistema de data space sanitario reducido con 4 pilares: HTTPS, autenticación robusta, persistencia cifrada/comprimida y flujo de datos armonizados/anónimos.  
Alcance fijado: obligatorios del PDF + 1 mejora adicional concreta: sesiones seguras con tokens aleatorios y expiración por inactividad.

## Flujo de trabajo
1. **Cerrar el modelo funcional antes de tocar seguridad**
   - Sustituir el flujo actual de “string privado por usuario” por registros sanitarios estructurados.
   - Definir dos modelos:
     - `LocalRecord`: armonizado, no anonimizado, guardado en cliente.
     - `AnonymizedRecord`: armonizado y anonimizado, enviado al servidor.
   - Esquema decidido para la práctica:
     - `ID`, `Classification`, `AgeRange`, `Sex`, `PatientAlias`, `Observation`, `CreatedAt`, `UploadedBy`.
     - En el servidor solo se conservan `ID`, `Classification`, `AgeRange`, `Sex`, `CreatedAt`, `UploadedBy`.
   - Reglas de armonización:
     - `AgeRange`: `0-17`, `18-35`, `36-50`, `51-65`, `66+`.
     - `Sex`: `M`, `F`, `X`, `ND`.
     - `Classification`: conjunto cerrado definido en constantes.
   - Persistencia local del cliente: XML propio almacenado en una DB local reutilizando `pkg/store`.

2. **Replantear interfaces públicas mínimas**
   - Cambiar `server.Run()` a `server.Run(Config)` para inyectar:
     - dirección HTTPS,
     - rutas de certificado/clave TLS,
     - clave maestra derivada,
     - rutas de DB de servidor y cliente.
   - Ampliar `api` con acciones nuevas:
     - `register`, `login`, `uploadRecord`, `getStats`, `logout`.
   - Ampliar `api.Request`/`api.Response` con:
     - `Role`,
     - `Record`,
     - `StatsQuery`,
     - `StatsRows`.
   - Mantener JSON en la API; usar XML solo como formato armonizado local del cliente.

3. **Implementar arranque seguro y transporte**
   - En `main`, pedir la contraseña maestra antes de arrancar el servidor.
   - Derivar una clave de 32 bytes con `argon2id` usando una sal persistente en `data/master.salt`.
   - Si no existe la sal, crearla en el primer arranque.
   - Generar certificado autofirmado para `localhost`/`127.0.0.1` si no existe y guardar en `data/tls/`.
   - Servidor en `https://localhost:8443`.
   - Cliente con `http.Client` + `tls.Config` confiando explícitamente en el certificado generado.

4. **Blindar autenticación, sesiones y autorización**
   - Reemplazar contraseñas en claro por `argon2id` con sal aleatoria por usuario.
   - Guardar usuarios como registro estructurado con `username`, `passwordHash`, `salt`, `role`.
   - Roles decididos:
     - `patient`: puede registrar, crear/subir registros y ver los suyos locales.
     - `analyst`: puede consultar estadísticas del servidor.
   - Bootstrap de autorización:
     - en el primer arranque, si no existe ningún `analyst`, pedir crear la cuenta inicial autorizada.
     - el alta normal desde cliente crea siempre usuarios `patient`.
   - Mejora adicional escogida:
     - tokens de sesión con `crypto/rand`, codificados en base64url,
     - expiración por inactividad de 30 minutos,
     - renovación del `LastSeen` en cada petición autenticada válida.

5. **Añadir cifrado y compresión en la capa de persistencia**
   - No reescribir la lógica de negocio por bucket; reutilizar `pkg/store` con un decorador.
   - Crear un `SecureStore` que envuelva al `Store` actual:
     - `Put`: serializar, comprimir con gzip, cifrar con AES-256-GCM, almacenar sobre el backend bbolt.
     - `Get`: descifrar, descomprimir y devolver el valor original.
   - Aplicar el decorador tanto a la DB del servidor como a la DB local del cliente.
   - Verificación de contraseña maestra:
     - guardar un registro centinela cifrado en la DB;
     - si al arrancar no se puede descifrar, abortar con error de clave maestra incorrecta.
   - Mantener claves y nombres de buckets en claro; cifrar todos los valores.

6. **Construir el flujo funcional de data space**
   - Menú `patient`:
     - crear registro armonizado,
     - listar registros locales,
     - subir registro anonimizado,
     - logout.
   - Menú `analyst`:
     - consulta estadística por `Classification + AgeRange`,
     - logout.
   - El cliente:
     - pide datos crudos,
     - armoniza,
     - guarda el XML no anonimizado en su DB local,
     - genera una copia anonimizada para subir al servidor.
   - El servidor:
     - almacena solo registros anonimizados,
     - calcula estadísticas agregadas,
     - bloquea `getStats` si el rol no es `analyst`.

## Casos de prueba y aceptación
- Registro y login con hash seguro; login correcto e incorrecto.
- Alta de `patient` sin posibilidad de autoasignarse `analyst`.
- Bootstrap inicial de `analyst` solo cuando no existe uno.
- Comunicación cliente-servidor por HTTPS válida; fallo si el cliente no confía en el certificado.
- Persistencia cifrada:
  - roundtrip `Put/Get`,
  - error con clave maestra incorrecta,
  - ausencia de texto sensible en claro en la DB.
- Flujo de registros:
  - creación local armonizada,
  - almacenamiento local no anonimizado,
  - subida anonimizada,
  - servidor sin `PatientAlias` ni `Observation`.
- Estadísticas:
  - `analyst` autorizado obtiene recuento por clasificación y rango de edad,
  - `patient` recibe rechazo.
- Sesiones:
  - token válido,
  - logout invalida,
  - expiración por inactividad rechaza peticiones posteriores.
- Validación final: `go test ./...` verde y memoria alineada con decisiones de seguridad tomadas.

## Suposiciones y decisiones por defecto
- Se mantiene la UI de terminal y el arranque conjunto cliente+servidor; no se migra a web.
- El formato armonizado de práctica será XML local propio; la API seguirá siendo JSON.
- La “BD del sistema” se protegerá cifrando todos los valores persistidos, no el fichero bbolt completo ni sus metadatos.
- Se reutilizará una única contraseña maestra para derivar la clave que protege tanto la DB del servidor como la DB local del cliente, porque la práctica arranca como una sola aplicación.
- La consulta estadística obligatoria mínima será una tabla agregada por `Classification` y `AgeRange`; no se añaden más consultas en esta iteración.
- La memoria debe documentar explícitamente: modelo de datos, anonimización, elección de Argon2id, uso de AES-GCM, gestión de la clave maestra, TLS local y limitaciones conocidas.
