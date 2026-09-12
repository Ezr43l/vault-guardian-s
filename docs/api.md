# API de Vault Guardian

La API HTTP permite consultar estado y solicitar operaciones declarativas sobre las
instancias configuradas. No es una API de Docker ni sustituye a floating-IP.

## Compatibilidad

- Base URL recomendada: `https://guardian.example.net` mediante un proxy HTTPS.
- El acceso directo `http://<nodo>:6062` sólo es apto para una red aislada y debe
  elegirse explícitamente durante el alta de la primera cuenta.
- API estable: rutas bajo `/api/v1`.
- `/api/health` y `/api/version` son comprobaciones públicas.
- Las rutas sin `/v1` son compatibilidad histórica.
- Las respuestas JSON usan UTF-8 y no deben cachearse.
- Los consumidores deben enumerar instancias y miembros; no asumir nombres ni cantidades.

Guardian sólo reclama una IP tras validar las réplicas. Keepalived conserva la elección
del portador y sólo éste puede originar una sincronización.

## Autenticación

Existen cinco ámbitos de credenciales separados:

| Canal | Credencial | Uso |
|---|---|---|
| Portal | cookie `vault_guardian_session` y CSRF | Acceso humano |
| Integración | `Authorization: Bearer <token de la aplicación>` | Otros contenedores |
| Interno | `X-Replication-Token: <VG_REPLICATION_TOKEN>` | Comunicación entre Guardian |
| Keepalived | `Bearer <VG_FLOATING_API_TOKEN>` saliente | Consultar y gestionar la IP flotante |
| Docker local | socket Unix local, sin endpoint de red | Operaciones internas del único contenedor |

Las lecturas y operaciones de Guardian aceptan sesión o Bearer. Las mutaciones mediante
sesión también requieren `X-CSRF-Token`; el valor se obtiene de
`GET /api/v1/session`. El Bearer no administra usuarios, otras aplicaciones API ni crea
sesiones. El secreto
interno nunca se entrega a consumidores. Guardian lo adjunta a las lecturas de estado
entre pares para calcular el grupo sin convertir esos endpoints en públicos; no autoriza
mutaciones administrativas.

`VG_FLOATING_API_TOKEN` no autentica consumidores de Vault Guardian. Es una credencial
saliente que Guardian utiliza exclusivamente al consultar portadores y gestionar
reclamaciones en la API de Keepalived.

## Sesión del portal

Estado público del subsistema:

~~~http
GET /api/v1/auth/status
~~~

Cuando `configured=false`, crear la primera cuenta:

~~~http
POST /api/v1/auth/setup
Content-Type: application/json

{
  "username": "usuario-elegido",
  "display_name": "Nombre visible",
  "password": "contraseña de 12+ caracteres",
  "password_confirmation": "contraseña de 12+ caracteres",
  "cluster_token": "opcional: código de un grupo existente"
}
~~~

Esta ruta no acepta sesión ni Bearer y sólo está abierta mientras no existe ningún
usuario. Sin `cluster_token`, el nodo usa el secreto generado en su volumen; con él adopta
el grupo indicado antes de crear la cuenta. Crea la revisión inicial, la distribuye a los
pares configurados e instala la cookie de sesión. Una segunda llamada devuelve
`409 AUTH_ALREADY_CONFIGURED`.

Crear sesión:

~~~http
POST /api/v1/session
Content-Type: application/json

{"username":"usuario","password":"contraseña","second_factor":"123456"}
~~~

`second_factor` puede omitirse si la cuenta no tiene 2FA. También acepta un código de
recuperación. La respuesta instala una cookie HttpOnly y devuelve `session.csrf_token`.

~~~http
GET /api/v1/session
DELETE /api/v1/session
~~~

`GET` devuelve usuario, nombre visible, 2FA, códigos restantes, CSRF y caducidad.
`DELETE` cierra la sesión.

## Usuarios, perfil y 2FA

Estas rutas sólo aceptan sesión. Las mutaciones requieren CSRF:

~~~http
GET  /api/v1/users
POST /api/v1/users
PUT  /api/v1/users/{username}
DELETE /api/v1/users/{username}
PUT  /api/v1/profile
POST /api/v1/profile/2fa/setup
POST /api/v1/profile/2fa/confirm
POST /api/v1/profile/2fa/disable
POST /api/v1/profile/recovery-codes
~~~

Alta de usuario:

~~~json
{"username":"operator","display_name":"Operación","password":"contraseña de 12+ caracteres"}
~~~

Edición administrativa:

~~~json
{"display_name":"Operación","enabled":true,"password":"nueva contraseña opcional"}
~~~

`/profile` acepta `display_name` y, para cambiar contraseña,
`current_password` más `new_password`. El usuario actual no puede eliminarse ni
deshabilitarse desde la lista.

El alta 2FA devuelve QR, URI y secreto manual. `confirm`, `disable` y
`recovery-codes` reciben `{"code":"123456"}`. Al confirmar o regenerar se devuelven
diez códigos de recuperación una sola vez.

## Salud y versión

No requieren autenticación:

~~~http
GET /api/health
GET /api/version
~~~

Ejemplo:

~~~json
{"estado":"ok","nodo":"nodo-1","modo":"observe","configurado":false,"version":"1.0.18"}
~~~

La salud de Guardian no sustituye la salud de Vaultwarden.

## Lecturas operativas

Requieren sesión o Bearer:

~~~http
GET /api/v1/status
GET /api/v1/cluster
GET /api/v1/instances
GET /api/v1/instances/{id}
GET /api/v1/config
GET /api/v1/setup
GET /api/v1/discovery
GET /api/v1/history?limit=100
GET /api/v1/cluster/enrollment-token
~~~

`status` es la lectura principal. `cluster` devuelve el agregado `protected`,
`degraded`, `unknown`, `conflict` o `unconfigured`. Sólo se considera protegido
cuando existen al menos dos nodos, todos responden, publican la misma huella y reconocen
un único portador.

`config` no devuelve tokens. `discovery` sólo enumera candidatos dentro de las raíces
autorizadas. `history` devuelve hasta 500 operaciones y no contiene secretos. Los límites
de persistencia se cambian en **Ajustes de la aplicación**; la consulta lee desde el final
sin cargar todo `history.jsonl`.

`cluster/enrollment-token` es la única lectura explícita del secreto del grupo y exige un
administrador autenticado. Se utiliza para dar de alta otro nodo; no forma parte de
`config`, `status`, el historial ni la plantilla.

La conexión con Keepalived se guarda mediante:

~~~http
PUT /api/v1/integrations/keepalived
Content-Type: application/json
X-CSRF-Token: <csrf de la sesión>

{"token":"fip_..."}
~~~

La respuesta sólo confirma `configured` y la URL; nunca devuelve el Bearer.

Los valores locales que antes se suministraban como variables Docker se administran con:

~~~http
PUT /api/v1/application-settings
PUT /api/v1/tls/private-ca
DELETE /api/v1/tls/private-ca
~~~

`application-settings` recibe `session_minutes`, `history_max_mb`,
`history_max_entries` y `allow_insecure_portal`. La CA se envía como
`{"pem":"-----BEGIN CERTIFICATE-----..."}`.

Las aplicaciones que consumen la API se administran únicamente con una sesión del portal:

~~~http
GET    /api/v1/integrations/applications
POST   /api/v1/integrations/applications
GET    /api/v1/integrations/applications/{id}/token
PUT    /api/v1/integrations/applications/{id}
POST   /api/v1/integrations/applications/{id}/rotate
DELETE /api/v1/integrations/applications/{id}
~~~

El alta recibe `{"name":"RTFM"}` y genera un Bearer seguro, o acepta además un `token`
elegido por el usuario. El inventario muestra nombre, pista del token, fechas, contador,
última ruta utilizada y si procede del antiguo `VG_API_TOKEN`. `PUT` cambia el nombre y,
opcionalmente, el token; `rotate` genera uno nuevo. Consultar el valor completo y cualquier
cambio exige una sesión humana; un Bearer no puede enumerar ni administrar otras
credenciales.

## Métricas y recuperación

Requieren sesión o Bearer:

~~~http
GET /metrics
GET /api/v1/metrics
GET /api/v1/instances/{id}/backups
POST /api/v1/instances/{id}/restore
~~~

Métricas usa texto Prometheus 0.0.4. El inventario de backups devuelve nombre, tamaño y
fecha, nunca contenido ni ruta. Restaurar requiere:

~~~json
{"backup":"antes-20260825-120000.vgb","confirm":true}
~~~

Se rechaza si falta confirmación, el modo no es `active`, la VIP es desconocida, el nodo
es portador o el contenedor no está en marcha. Guardian crea un backup de seguridad antes
de aplicar.

## Validación y configuración

Requieren sesión o `Authorization: Bearer <token de la aplicación>`. Las mutaciones con sesión añaden `X-CSRF-Token`:

~~~http
POST /api/v1/instances/validate
POST /api/v1/instances
PUT /api/v1/instances/{id}
DELETE /api/v1/instances/{id}
PUT /api/v1/cluster/policy
PUT /api/v1/cluster/configuration
~~~

El cuerpo de una instancia es:

~~~json
{
  "id": "vaultwarden-1",
  "container": "vaultwarden-1",
  "data_dir": "/instances/vaultwarden-1",
  "health_port": 8080,
  "health_path": "/api/version",
  "floating_service": "vaultwarden-1",
  "include_sends": true,
  "replication_enabled": false
}
~~~

Campos obligatorios: `id`, `container`, `data_dir`,
`health_port` y `health_path`. Los valores por defecto son
`floating_service=id`, `include_sends=true` y
`replication_enabled=false`.

Restricciones relevantes:

- `data_dir` debe ser una ruta absoluta, existir dentro del contenedor y estar
  dentro de alguna raíz de `VG_DATA_ROOTS`.
- `health_path` debe empezar por `/`.
- La configuración se valida contra el contenedor declarado, su salud HTTP y el servicio
  de IP flotante antes de considerarse válida.
- `PUT` reemplaza la definición completa; el `id` de la ruta no se puede
  cambiar.
- `DELETE` sólo elimina la definición de `instances.json`; no borra datos,
  volúmenes ni contenedores.
- Una instancia nueva queda con replicación desactivada salvo que el usuario la habilite
  explícitamente.

Validar no escribe configuración:

~~~bash
curl -fsS -X POST https://guardian.example.net/api/v1/instances/validate \
  -H "Authorization: Bearer $VAULT_GUARDIAN_APP_TOKEN" \
  -H "Content-Type: application/json" \
  --data @instancia.json
~~~

Crear, actualizar o eliminar una instancia valida primero todos los Guardian accesibles
y aplica la misma definición en el grupo. Si la validación de un miembro falla, no se
inicia la aplicación.

`PUT /api/v1/cluster/policy` cambia de una vez `mode`, `interval_seconds`,
`backup_retention` y `max_package_mb` (entre 1 y 256 MiB). Pasar a `active` requiere
`"confirm_active": true` y afecta a la capacidad de todo el grupo, no al liderazgo.

`PUT /api/v1/cluster/configuration` se usa para la instalación inicial o reparación:
recibe `local_name`, la lista `members` y la política. Cada miembro declara `name`,
`guardian_url`, `node_ip` y `floating_api`. `vaultwarden_root` se conserva como
compatibilidad para instalaciones anteriores, pero no es un requisito operativo.

Al guardar la configuración, Guardian compara el inventario de todos los miembros. Si el
grupo está en `active`, cualquier instancia ausente se crea automáticamente en el servidor
nuevo desde el portador saludable de su IP y después se sincroniza el grupo completo. La
respuesta incluye `reconciliacion` e `identidades`. Este último objeto informa de los
miembros `updated` y `failed` al distribuir el almacén de cuentas existente, incluida
la primera cuenta creada antes de formar el grupo. No se reclama una IP nueva para un
servicio histórico.

## Reconciliación de servidores

Requiere sesión o `Authorization: Bearer <token de la aplicación>`. Con sesión, la escritura añade `X-CSRF-Token`:

~~~http
POST /api/v1/reconciliation
~~~

~~~json
{"confirm":true}
~~~

Sirve para comprobar o reintentar la incorporación después de reparar conectividad,
puertos o carpetas. La operación:

1. detecta instancias presentes en el grupo pero ausentes en algún miembro;
2. exige un único portador confirmado y saludable como origen;
3. reutiliza el preflight, la instantánea cifrada y el alta idempotente de F20;
4. sincroniza finalmente esa instancia con todos los miembros;
5. devuelve `reconciliado` sólo si el clúster termina `protected`.

En `observe` o `dry-run` no crea contenedores y devuelve
`pendiente_modo_activo`. Una carpeta no vacía, un puerto ocupado, un servidor
inaccesible o un conflicto de huellas bloquean la operación sin sobrescribir datos.

## Alta automática de Vaultwarden

Requiere sesión o `Authorization: Bearer <token de la aplicación>`. Con sesión, la escritura añade `X-CSRF-Token`:

~~~http
GET /api/v1/provisioning/candidates
POST /api/v1/provisioning
GET /api/v1/provisioning/transactions/{transaction}
~~~

`candidates` enumera sólo contenedores que usan la imagen oficial de Vaultwarden. Devuelve
imagen, digest, puerto, origen de `/data` y nombres de variables; nunca devuelve sus valores.

`POST /api/v1/provisioning` exige una cabecera `Idempotency-Key` estable y un cuerpo:

~~~json
{
  "source_container": "vaultwarden-source",
  "instance_id": "vaultwarden-1",
  "display_name": "Vaultwarden 1",
  "data_directory": "vaultwarden-1",
  "destination_paths": {
    "nodo-2": "/mnt/user/appdata/vaultwarden-1",
    "nodo-3": "/mnt/cache/appdata/vaultwarden-1"
  },
  "health_path": "/alive",
  "include_sends": true,
  "confirm": true
}
~~~

`destination_paths` se exige sólo para los servidores donde se creará una réplica.
Cada valor es una ruta host completa dentro de la raíz montada en `/instances` de ese
Guardian. El destino puede ser una carpeta vacía existente; si no existe, Guardian crea
la carpeta final. Nunca sobrescribe un directorio que ya contenga datos.

El grupo debe estar en `active` y tener configurado el secreto entre Guardian. La operación valida
todos los destinos, crea las réplicas detenidas, copia una instantánea cifrada, las
arranca, comprueba salud, registra la instancia y reclama la IP en último lugar. Si se
interrumpe, repetir exactamente el mismo cuerpo y la misma `Idempotency-Key` continúa
la transacción sin duplicar recursos.

El endpoint de transacción devuelve `stage`, `nodes`, `floating_ip`, `complete`,
`failed_at` y un error acotado. No devuelve variables ni secretos.



## Sincronización solicitada

Requiere sesión o `Authorization: Bearer <token de la aplicación>`. Con sesión, la escritura añade `X-CSRF-Token`:

~~~http
POST /api/v1/instances/{id}/sync
~~~

Ejemplo:

~~~bash
curl -fsS -X POST https://guardian.example.net/api/v1/instances/vaultwarden-1/sync \
  -H "Authorization: Bearer $VAULT_GUARDIAN_APP_TOKEN"
~~~
El cuerpo puede omitirse o ser un objeto JSON vacío; ambos casos permiten reutilizar la conexión.

La petición puede enviarse a cualquier Guardian. El receptor consulta Floating IP,
resuelve el portador actual de esa instancia y reenvía allí la ejecución. No ejecuta ni
sincroniza las demás instancias.


Semántica:

- `observe`: no prepara ni escribe nada.
- `dry-run`: crea y valida el paquete, pero no lo envía.
- `active`: sólo el portador de la VIP puede enviar; un Guardian pasivo encamina la
  solicitud manual hacia él.
- `replication_enabled=false`: la instancia queda bloqueada en ambos sentidos.
- El receptor deduplica por contenido; una réplica idéntica devuelve `sin_cambios` y no
  detiene ni reinicia el contenedor.
- Una aplicación nueva crea primero un respaldo local y sólo sustituye el contenedor y
  datos declarados para esa instancia.

Estados principales de la respuesta:

| Estado | Significado |
|---|---|
| `deshabilitado` | Replicación desactivada o `observe` |
| `en_espera` | El ciclo automático de este Guardian espera al portador de la VIP |
| `bloqueado` | Falta una condición operativa, como el token o la VIP |
| `preparado` | Paquete creado en `dry-run` |
| `sincronizado` | Todos los pares configurados confirmaron la entrega |
| `degradado` | Sólo una parte de los pares confirmó la entrega |
| `sin_destinos` | No hay pares configurados; no existe redundancia |
| `sin_cambios` | El receptor ya tiene la misma huella de contenido |
| `conflicto` | El paquete no desciende del estado local y se ha rechazado |
| `error` | No se pudo preparar o ningún par confirmó la entrega |

El consumidor puede usar `estado`, `destinos_ok` y `destinos_esperados`; los
detalles de cada entrega siguen disponibles en `pares`.

## Endpoint interno de recepción

No forma parte del contrato para consumidores externos:

~~~http
POST /api/v1/internal/replication/{id}
POST /api/v1/internal/sync/{id}
POST /api/v1/internal/provisioning/preflight
POST /api/v1/internal/provisioning/prepare
POST /api/v1/internal/provisioning/{transaction}/snapshot
POST /api/v1/internal/provisioning/{transaction}/activate
PUT /api/v1/internal/security
PUT /api/v1/internal/policy
PUT /api/v1/internal/settings
PUT /api/v1/internal/instance-config
X-Replication-Token: <VG_REPLICATION_TOKEN>
X-VG-Source-Node: <nodo-origen>
Content-Type: application/octet-stream
~~~

Estas rutas sólo se usan entre Guardian. `replication` comprueba el token, el origen,
el portador de la VIP, el modo `active`, la instancia habilitada y el manifiesto antes
de parar el contenedor. Las demás permiten encaminar una sincronización, distribuir configuración y replicar el estado versionado de usuarios con validación previa. No se deben llamar desde un orquestador
externo ni exponer a consumidores.

## Errores y reintentos

Las respuestas de error tienen esta forma:

~~~json
{"error":"mensaje en español"}
~~~

| HTTP | Uso |
|---:|---|
| 200 | Lectura u operación aceptada |
| 201 | Instancia creada |
| 204 | `OPTIONS` |
| 400 | Ruta o petición inválida |
| 401 | Credenciales ausentes o no válidas |
| 403 | CSRF ausente o no válido |
| 422 | Cuerpo válido pero datos rechazados |
| 429 | Límite de intentos de login |
| 503 | Servicio o configuración imprescindible no disponible |
| 404 | Instancia o ruta inexistente |
| 409 | Configuración o condición operativa rechazada |
| 500 | Fallo interno al aplicar una operación |

Los consumidores pueden reintentar lecturas. Para `sync` conviene esperar el resultado
antes de repetir: la operación es deduplicable por contenido, pero un reintento debe
interpretar `sin_cambios` como éxito operativo. No se deben lanzar sincronizaciones
concurrentes para la misma instancia.

## Seguridad operativa

- No hay endpoint para ejecutar comandos Docker arbitrarios.
- El contenedor que puede detenerse sale de la configuración validada.
- No se permite que `data_dir` escape de las raíces montadas.
- El único contenedor monta el socket Docker y valida una lista blanca dinámica de
  Vaultwarden, réplicas administradas y rutas `/data` bajo `/instances`.
- Portal, integraciones y replicación usan credenciales separadas.
- Las contraseñas usan scrypt; TOTP se cifra y las recuperaciones se almacenan como hashes.
- Las mutaciones de sesión exigen CSRF y la cookie es HttpOnly y SameSite=Strict.
- Para integrar otro contenedor, usar lecturas `/api/v1` y `sync`; no leer
  `instances.json` ni el estado interno de `/state`.

## Readiness y baseline

Lectura pública para integraciones de alta disponibilidad:

~~~http
GET /api/v1/instances/{id}/readiness
~~~

Devuelve 200 cuando el nodo es apto y 503 cuando se debe excluir. La respuesta incluye
`role`, `porter`, `cluster_state`, `fingerprint` y una lista `reasons` estable.

El baseline administrativo se usa para incorporar o migrar nodos sin confiar en una
huella histórica:

~~~http
POST /api/v1/instances/{id}/baseline
Cookie: vg_session=...  # o Authorization: Bearer <token de la aplicación>
X-CSRF-Token: <token>  # sólo con sesión
Content-Type: application/json
~~~

La primera llamada usa `{"confirm":false}` y sólo calcula. Después de comparar todos los
nodos, se confirma con `{"confirm":true,"expected_fingerprint":"<sha256>"}`. Si el
contenido local no coincide exactamente, la operación se rechaza y no cambia el estado.
