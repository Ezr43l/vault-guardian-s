# Cambios

## [v1.0.19] - 2026-09-13 · MEJORA

### Añadido

- Añadido en el acceso y en el pie del panel el enlace de soporte a la comunidad de
  Discord de Unraides.
- La plantilla pública sigue el canal `stable`.

## [v1.0.18] - 2026-09-12 · CORRECCIÓN

### Corregido

- El laboratorio de publicación amplía su ventana de observación para que la
  comprobación ARM64 ejecutada mediante QEMU no confunda un arranque lento con un
  contenedor no saludable. La configuración de salud de la imagen no cambia.

## [v1.0.17] - 2026-09-11 · CORRECCIÓN

### Corregido

- La imagen base oficial queda fijada a Python 3.12 sobre Alpine 3.23 y se actualiza
  durante la construcción, eliminando las vulnerabilidades altas detectadas en `libuuid`.
- Las puertas de CI obtienen la versión desde `VERSION`, validan el contrato real de la
  plantilla y superan el lint antes de permitir una publicación.

## [v1.0.16] - 2026-09-10 · CORRECCIÓN

### Corregido

- La conexión con Keepalived alinea el campo y sus acciones en una única fila de
  controles, con alturas y separación homogéneas.
- La gestión de aplicaciones API iguala campos, ayudas y botones tanto al crear como al
  editar credenciales.
- Las tarjetas «Mi cuenta» y «Autenticación de dos factores» comparten estructura,
  altura de sus barras principales y alineación inferior de acciones.
- El ejemplo Compose vuelve a declarar la misma versión que `VERSION`, la plantilla y la
  imagen, evitando que el contrato de CI falle después de publicar el commit.
- La validación de la plantilla reconoce sus cuatro parámetros Docker reales, sin confundir
  la raíz montada de Vaultwarden con una variable de configuración de la aplicación.
- El workflow de release supera también el lint de sus scripts embebidos sin variables de
  iteración declaradas y no utilizadas.

## [v1.0.15] - 2026-09-10 · CORRECCIÓN

### Corregido

- La opción HTTP del grupo vuelve a tener tamaño de control normal y queda agrupada bajo
  «Comunicación interna», con su alcance y efecto explicados junto al selector.
- El token API único se sustituye por aplicaciones identificadas, cada una con su propio
  Bearer, contador y último uso. El portal permite crear, renombrar, consultar, sustituir
  o revocar cada credencial de forma independiente.
- El token anterior se conserva sin cambios y aparece como una integración heredada para
  que pueda identificarse sin interrumpir a su consumidor actual.

## [v1.0.14] - 2026-09-10 · CORRECCIÓN

### Corregido

- La raíz global de futuras réplicas deja de figurar como requisito pendiente del
  sistema y desaparece de la configuración ordinaria del grupo.
- El alta automática solicita en ese momento una ruta host completa por servidor de
  destino, dentro del montaje autorizado de Vault Guardian.
- Una carpeta de destino vacía se reutiliza; si falta, Guardian crea exclusivamente la
  carpeta final. Los directorios con datos, enlaces o rutas fuera del montaje se rechazan.

## [v1.0.13] - 2026-09-10 · CORRECCIÓN

### Corregido

- El descubrimiento omite directorios ajenos que no puede inspeccionar en la raíz
  montada, sin modificar sus permisos ni abortar la API y el panel completo.

## [v1.0.12] - 2026-09-10 · CORRECCIÓN

### Corregido

- Un receptor conserva el límite de una sola carga grande, pero espera de forma acotada
  cuando otra réplica está terminando en vez de rechazarla inmediatamente.
- El emisor reintenta de forma acotada un `503` transitorio del receptor, sin reintentar
  errores de autenticación, autoridad, integridad o aplicación.

## [v1.0.11] - 2026-09-10 · CORRECCIÓN

### Corregido

- Las operaciones de datos se serializan por instancia y no mediante un bloqueo global.
  Dos Vault distintos pueden replicarse simultáneamente sin que sus portadores se esperen
  entre sí; las operaciones concurrentes sobre el mismo Vault continúan serializadas.

## [v1.0.10] - 2026-09-10 · CORRECCIÓN

### Corregido

- El portador único confirmado por Keepalived vuelve a ser la autoridad efectiva de cada
  Vaultwarden: una divergencia en un nodo pasivo ya no bloquea indefinidamente la réplica.
- Antes de sustituir datos divergentes, el receptor conserva su snapshot local; si la
  aplicación falla, restaura automáticamente ese backup.
- Las aplicaciones correctas quedan registradas como `aplicado`, junto con la autoridad,
  las huellas anterior/aplicada y el motivo de la reconciliación.
- Al completarse la sincronización se aplica la retención configurada, evitando que los
  reintentos fallidos sigan acumulando backups de conflicto.

## [v1.0.9] - 2026-09-09 · CORRECCIÓN

### Corregido

- La réplica deja de crear contenedores auxiliares: el único Vault Guardian accede
  directamente a una raíz de datos autorizada montada en `/instances`.
- La correspondencia entre cada bind `/data` de Vaultwarden y su ruta dentro de Guardian
  se valida contra Docker antes de leer o escribir.
- La plantilla Unraid incorpora únicamente el montaje imprescindible de la raíz appdata;
  el resto de la configuración continúa dentro del portal.
- Se elimina el fallo `container rootfs is marked read-only` que impedía crear snapshots
  y mantenía las instancias en conflicto.

## [v1.0.8] - 2026-09-09 · CORRECCIÓN

### Corregido

- La configuración autenticada incorpora duración de sesión, límites del historial y
  selección HTTP/HTTPS, aplicados sin recrear el contenedor.
- El token Bearer para integraciones se puede crear, sustituir o desactivar desde el
  portal sin mostrar nunca el valor persistido.
- Una CA privada puede pegarse y retirarse desde la aplicación; ya no necesita una ruta
  ni un montaje adicional en la plantilla.
- Los valores heredados del entorno se conservan como migración inicial, pero dejan de
  bloquear los cambios explícitos realizados dentro de la aplicación.
- Compose y Unraid mantienen únicamente imagen/metadatos, puerto, estado persistente y
  socket Docker; la configuración funcional queda en el portal.

## [v1.0.7] - 2026-09-07 · CORRECCIÓN

### Corregido

- La autorización de HTTP interno se guarda ahora con la topología dentro de la app y deja de depender de una variable Docker.
- La pantalla de grupo pide expresamente esa autorización cuando Guardian o Keepalived usan HTTP en una LAN o VPN aislada.

## [v1.0.6] - 2026-09-07 · CORRECCIÓN

### Corregido

- La plantilla Unraid queda reducida a puerto, volumen persistente y socket
  Docker. El modo HTTPS o HTTP aislado se elige al crear la primera cuenta.
- La elección se conserva en `/state/portal-access.json` con modo `0600`; las
  instalaciones antiguas que usan `VG_ALLOW_INSECURE_PORTAL` mantienen
  precedencia.
- La primera respuesta de alta emite una cookie coherente con el transporte
  elegido, sin editar ni reiniciar el contenedor.

## [v1.0.5] - 2026-09-07 · CORRECCIÓN

### Corregido

- La plantilla Unraid pasa de 22 campos a 4 y conserva únicamente puerto,
  volumen, socket Docker y la decisión HTTP necesaria antes del primer login.
- El secreto local del grupo se genera de forma segura dentro de `/state`; un
  nodo nuevo puede adoptar el código de un grupo existente durante su alta.
- El Bearer generado por Keepalived se introduce desde el portal autenticado y
  se persiste sin devolver su valor en la configuración pública.
- La conexión local usa `host.docker.internal` mediante el gateway técnico de
  Docker, eliminando direcciones de servidor de la plantilla.
- Vault Guardian consume el contrato idempotente de Keepalived 0.14.1 para
  reservar y liberar VIP sin duplicados.

## [v1.0.4] - 2026-09-07 · CORRECCIÓN

### Corregido

- Vault Guardian vuelve a instalarse y ejecutarse como una sola aplicación y un único
  contenedor, tanto con Compose como con la plantilla Unraid.
- El acceso Docker se realiza mediante un único montaje local de `docker.sock`; se eliminan
  el sidecar, su red, su plantilla y su token interno.
- El despliegue migra el contenedor principal con rollback y, sólo después de comprobar su
  salud y versión, retira los restos de la arquitectura anterior.
- Plantillas, ejemplos y documentación quedan alineados con `1.0.4` y no contienen datos de
  una instalación particular.

## [v1.0.3] - 2026-09-01 · CORRECCIÓN

### Corregido

- La publicación espera a que GitHub haga visible el borrador recién creado antes de
  validarlo y convertirlo en una release inmutable.

## [v1.0.2] - 2026-09-01 · CORRECCIÓN

### Corregido

- La recuperación de drafts resuelve un único candidato por tag mediante el listado
  paginado de releases; la creación adjunta los assets directamente y no depende de
  `releases/tags` ni de una subida posterior.

## [v1.0.1] - 2026-09-01 · CORRECCIÓN

### Corregido

- El despliegue deja de depender de una carpeta de secretos y un registro pertenecientes
  al entorno de desarrollo; usa rutas locales/Unraid genéricas y la imagen pública de GHCR.
- Los valores inseguros de HTTP quedan desactivados por defecto y la ruta de estado del
  despliegue coincide con la plantilla Unraid.
- Plantillas, Compose y documentación apuntan a `Ezr43l/vault-guardian-s` y a la versión
  `1.0.1`.
- `build-image.sh` sólo construye imágenes locales; publicar queda reservado al workflow
  explícito de release del repositorio público.

## [v1.0.0] - 2026-08-29 · RELEASE ESTABLE

### Añadido

- Alta automática de una instancia oficial de Vaultwarden a partir de un único origen:
  descubre su configuración permitida, valida todos los destinos, crea las réplicas,
  aplica una instantánea cifrada, comprueba su salud y reserva una IP flotante libre sólo
  cuando el servicio completo está preparado.
- Incorporación de nuevos servidores a un grupo existente: detecta qué réplicas faltan,
  encamina cada trabajo al portador fiable de la VIP y crea únicamente los destinos
  ausentes, sin reclamar una segunda dirección.
- Reintento explícito de reconciliación desde la interfaz y la API, con estado por trabajo
  y convergencia final comprobada.

### Cambiado

- El grupo se administra desde un único panel y admite N servidores y N instancias sin
  nombres, IPs, rutas ni topologías predeterminadas.
- La protección, la sincronización por instancia y el alta muestran inicio, alcance,
  progreso, destinos y resultado final.
- La especificación privada del contenedor y las instantáneas viajan selladas con la
  credencial entre Guardian; los secretos no aparecen en inventarios, historial ni estado
  persistente.

### Corregido

- La plantilla compartible apunta a la misma versión que `VERSION`; una prueba de
  empaquetado impide que vuelva a quedarse anclada a una imagen anterior.
- La actualización de la plantilla conserva los montajes existentes e instala los nuevos
  campos de cuenta, sesión y credenciales con los valores utilizados por el despliegue,
  sin incorporar datos privados a la plantilla compartible.
- Las lecturas de estado entre Guardian se autentican con el secreto interno; el grupo
  conserva su cálculo completo sin reabrir los endpoints operativos al acceso público ni
  permitir mutaciones con esa credencial.
- El cliente de IP flotante autentica con un Bearer específico las consultas de portador,
  las reclamaciones y las liberaciones. La plantilla compartida monta ese secreto desde un
  fichero `0400` y sólo expone en el entorno la ruta `VG_FLOATING_API_TOKEN_FILE`, nunca el
  valor Bearer.
- Las operaciones parciales conservan un estado degradado o pendiente y no presentan un
  servicio como protegido hasta confirmar todas las réplicas.
- El aprovisionamiento reanudable rechaza carpetas no vacías, puertos ocupados,
  contenedores ajenos e imágenes no oficiales o no fijadas.

### Seguridad y experiencia de producto

- `history.jsonl` queda acotado por tamaño y entradas configurables, con rotación atómica
  `0600`, lectura inversa con memoria e I/O acotados y rechazo de enlaces o tipos inseguros.
- El portal deja de montar `docker.sock`: un controlador autenticado y sin puerto publicado
  valida de nuevo cada inventario, imagen, helper, ruta y réplica antes de operar con Docker.
- El contenedor web se ejecuta sin root, con filesystem de sólo lectura, capabilities
  eliminadas y secretos opcionales mediante ficheros regulares acotados.
- El cliente HTTP común rechaza esquemas ambiguos, credenciales en URL, redirecciones,
  proxies heredados y respuestas sin límite; admite CA privada y exige aceptación explícita
  para enlaces internos sin TLS.
- Dependencias y base quedan fijadas; CI y release añaden auditoría, builds AMD64/ARM64,
  Trivy, SBOM, provenance, attestations y digest verificable.
- El token compartido con `docker-control` usa permisos DAC de grupo sin devolver
  capabilities al sidecar; los paquetes quedan limitados a 256 MiB, la expansión a 1 GiB
  y tanto el backend directo como los helpers trabajan con un tmpfs de hasta 2 GiB y margen
  tar explícito.
- El lector TAR cuenta también cabeceras PAX/GNU ocultas, limita su anidamiento y rechaza
  rutas de contenido por encima de la profundidad que puede generar Guardian. El canal de
  archivos de `docker-control` serializa tanto subidas como descargas grandes.
- Las nuevas réplicas sólo pueden montar una carpeta hija directa de la raíz host declarada;
  una ruta anidada o normalizada de forma ambigua se rechaza antes de llegar al daemon.
- Una sincronización sin credenciales se rechaza antes de leer su cuerpo, de modo que no
  puede ocupar los hilos acotados del portal mediante una carga lenta no autenticada.
- La plantilla Unraid monta también replicación, floating-ip y API desde ficheros de sólo
  lectura; ningún valor secreto queda almacenado en las variables visibles por Docker.
- La misma `v1.0.0` sustituye el desbloqueo por contraseña compartida por un portal de
  login con cuentas locales, contraseñas scrypt, sesiones firmadas y protección CSRF.
- Gestión de usuarios desde la interfaz, perfil propio, activación TOTP mediante QR y diez
  códigos de recuperación de un solo uso.
- El estado de identidades se cifra cuando corresponde, se versiona y se distribuye entre
  los Guardian del grupo mediante la credencial interna.
- Rediseño completo con la estructura, paleta, tipografía, densidad, estados y controles
  del sistema visual común de Keepalived y NPM Guardian.
- La navegación queda reducida a cinco áreas operativas: Resumen, Grupo, Vaultwarden,
  Operación y Seguridad. Se elimina por completo la antigua sección Referencia.
- Resumen pasa a ser el panel operativo principal: reúne disponibilidad de servidores,
  cobertura de Vaultwarden, política, incidencias, estado por servicio y actividad reciente.
- Grupo muestra fuera del diagnóstico sólo los requisitos pendientes. La auditoría completa,
  cada servidor y los ajustes secundarios de política quedan plegados para conservar una
  vista compacta.
- Operación separa servidores y aplicaciones Vaultwarden en bloques distintos y pagina el
  historial con un máximo de diez registros por página.
- Las tarjetas de Vaultwarden se simplifican, admiten textos largos sin desbordamiento y
  eliminan el detalle técnico que no aportaba una acción útil al operador.
- La actualización periódica deja de reconstruir la vista Vaultwarden mientras está activa;
  el estado puede refrescarse de forma explícita sin cerrar controles ni provocar parpadeos.
- Segunda revisión visual de las cinco vistas: Topología y Protección separan de forma
  inequívoca el nombre y el estado de cada nodo, y los miembros usan tarjetas de estado
  de ancho uniforme.
- La cabecera móvil adapta el acceso a cuenta y salida sin recortar controles; formularios,
  usuarios, datos técnicos e historial ajustan su rejilla sin desbordamiento horizontal
  entre 360 y 1440 píxeles.
- Login independiente de Vaultwarden, navegación uniforme y acceso a la cuenta en la
  cabecera. Todas las confirmaciones pertenecen a la app.
- Cabeceras de seguridad, cookie HttpOnly/SameSite, sesiones Secure bajo HTTPS, limitación
  de intentos y eliminación de CORS comodín.
- La instalación ya no recibe un usuario o contraseña inicial desde la plantilla: el
  operador crea la primera cuenta con sus propias credenciales en un portal de alta que
  se cierra después del primer uso y distribuye la identidad al grupo.
- Si esa cuenta se creó antes de añadir pares, guardar los servidores del grupo distribuye
  automáticamente el estado de identidad vigente y muestra los miembros actualizados o
  pendientes.

## 0.8.2 — alta visible de servidores

- «Servidores del grupo» pasa a ser una sección principal de Configuración y deja de
  estar escondida dentro de opciones avanzadas.
- El botón «Añadir servidor» crea tarjetas numeradas con explicaciones para nombre,
  IP fija, URL de Guardian y URL de floating-IP.
- La administración puede desbloquearse dentro del propio gestor de servidores, sin
  obligar a regresar a Inicio.
- Un único formulario permite añadir, editar o excluir miembros y sólo aplica cambios
  al pulsar «Guardar servidores del grupo».
- La plantilla explica que se instala igual en cada servidor y que los N miembros se
  añaden dinámicamente desde un solo panel; no impone huecos ni nombres predeterminados.
- La ayuda y la guía de la plantilla documentan el alta de nuevos servidores.
- El despliegue instala el icono desde el propio Guardian de cada servidor, aborta ante
  cualquier fallo y compara los hashes de las dos cachés de Unraid.
- Validación de sintaxis y 59 pruebas automatizadas.

## 0.8.1 — un grupo, una configuración

- La política operativa se guarda una vez desde cualquier panel y se distribuye a todos los Guardian.
- El alta o reparación inicial permite declarar los N servidores en un único formulario; Guardian genera para cada uno su identidad local y la lista correcta de pares.
- Las altas, ediciones y bajas de Vaultwarden se validan y aplican en todo el grupo.
- «Sincronizar sólo Vaultwarden N» resuelve automáticamente qué Guardian porta su IP flotante y ejecuta allí únicamente esa instancia.
- Cada tarjeta conserva un mensaje de inicio, ejecución, destinos y finalización; la operación deja de parecer silenciosa o global.
- Los Guardian pasivos muestran «En espera del portador» y no registran falsos fallos por no sostener la VIP.
- La activación se explica como una política de grupo: todos quedan habilitados, pero sólo el portador envía y los pasivos reciben.
- La identidad, IP y API local siguen siendo distintas por servidor, pero quedan como diagnóstico avanzado generado desde el único formulario.
- Interfaz revisada visualmente en escritorio y móvil, prueba funcional con tres Guardian temporales y 56 pruebas automatizadas.

## 0.8.0 — plantilla clara e interfaz guiada

- Plantilla Unraid reducida a cinco campos visibles y dos opciones avanzadas.
- Identidad, red, pares, modo, intervalo, retención y límite se configuran desde el panel.
- Cinco vistas independientes: Inicio, Configuración, Vaultwarden, Operación y Ayuda.
- Inicio calcula el siguiente paso y explica qué falta sin exponer variables internas.
- Cada servicio tiene un nombre visible, como Vaultwarden 1 o Vaultwarden 2, separado de su ID y contenedor técnicos.
- Las instancias se muestran como tarjetas; rutas, contenedores e identificadores quedan plegados.
- El despliegue migra siempre las plantillas instaladas, conserva contraseñas y rutas elegidas y elimina campos heredados.
- Validación visual en escritorio y móvil, sintaxis JavaScript y 46 pruebas automatizadas.

## 0.7.1 — compatibilidad HTTP de la API

- `POST /sync` consume de forma segura un cuerpo opcional antes de responder.
- Las conexiones HTTP persistentes pueden reutilizarse después de sincronizar.
- Prueba de regresión que envía `{}` y consulta salud sobre la misma conexión.


## 0.7.0 — versión estable F11–F16

- Endpoint público por instancia para decidir de forma conservadora si un nodo puede portar la VIP.
- Los candidatos exigen contenedor activo, huella confirmada, ausencia de conflicto y réplica reciente.
- Baseline administrativo en dos pasos para migrar estados anteriores verificando la misma huella.
- El panel explica por instancia si el nodo está listo para la VIP y muestra los motivos de bloqueo.
- Estructura HTML corregida y protegida por pruebas de anidación, rutas HTTP y sintaxis JavaScript.
- El despliegue conserva la versión anterior hasta superar salud y la restaura automáticamente si falla.
- README de producto sin inventario ni topología de la instalación de referencia.
- El despliegue admite N montajes declarados sin asumir una raíz de datos única.
- El dry-run termina antes de conectar o comprobar nodos.

## 0.7.0-dev4 — panel operativo F15

- Navegación fija por resumen, clúster, instancias, actividad, recuperación y configuración.
- Estado agregado visible con número de nodos accesibles, portador y huellas confirmadas.
- Sincronización manual por instancia desde la interfaz, respetando todas las barreras backend.
- Historial persistente de operaciones accesible desde el panel administrativo.
- Estados protegido, degradado, desconocido y conflicto con semántica visual consistente.
- Pruebas de estructura, IDs únicos, endpoints reales, CSS y ausencia de nombres privados.

## 0.7.0-dev3 — configuración persistente y asistente F14

- Asistente real para identidad, red, pares, floating-ip, modo, intervalos y retención.
- Configuración operativa validada en /state/settings.json, con escritura atómica.
- La interfaz distingue lo que se configura en Unraid de lo que se guarda en Guardian.
- Activar escrituras exige confirmación explícita y cambiar identidad queda bloqueado
  cuando ya existen instancias.
- El ciclo automático permanece disponible si el usuario cambia de observe a active
  sin recrear el contenedor.
- La plantilla reduce los campos visibles y deja la configuración operativa al asistente.

## 0.7.0-dev2 — estado persistente y protección de linaje F13

- Último resultado e historial de operaciones persistentes y consultables tras reinicios.
- Estado agregado del clúster que diferencia protegido, degradado, desconocido,
  conflicto y sin configurar; una instalación sin redundancia nunca aparece protegida.
- Huellas de contenido y linaje de hasta 64 ancestros en cada paquete de réplica.
- Rechazo seguro de réplicas obsoletas, ramas divergentes y cambios locales no registrados.
- Resultado de envío veraz: sincronizado, degradado, error o sin destinos.
- Copia de seguridad consistente antes de comparar o modificar el destino.
## 0.7.0-dev1 — contrato de producto y empaquetado F11/F12

- Contrato de estados verificables, navegación y fuente única para cada decisión.
- Prototipo navegable con ocho rutas y escenarios saludable, degradado, desconocido,
  conflicto e instalación vacía.
- Nuevo icono PNG de Vault Guardian en 512, 128 y 64 píxeles con transparencia real.
- Plantilla Unraid corregida: publica el puerto 6062 como puerto Docker y declara el
  icono servido por la aplicación.
- Pruebas automáticas para el icono, la plantilla y la ausencia de nombres privados.

## 0.6.1 — plantilla generalista y guía de configuración

- La plantilla Unraid compartible deja de usar marcadores internos o datos de una instalación concreta.
- Build y despliegue reciben registros y nodos mediante variables, sin infraestructura incorporada.
- La interfaz explica el flujo y usa ejemplos Vaultwarden 1 / Vaultwarden 2.
- Nueva guía de plantilla, primer arranque, modos y replicación para operadores externos.

## 0.6.0 — observabilidad y recuperación F10

- Endpoint Prometheus de sólo lectura en `/metrics` y `/api/v1/metrics`.
- Inventario administrativo de backups por instancia mediante `/api/v1/instances/{id}/backups`.
- Restauración administrativa protegida: exige confirmación, nodo active, VIP en otro nodo y backup de seguridad previo.
- Retención configurable con `VG_BACKUP_RETENTION`, por defecto 5 y limitada entre 1 y 1000.
- El panel muestra los backups y guía la recuperación sin asumir nombres ni rutas.
- F10 validada con pruebas automatizadas de configuración y retención.

## 0.5.1 — huella recursiva de contenido F7

- El manifiesto incluye hashes de los archivos anidados en attachments y sends.
- La deduplicación ya detecta cambios reales dentro de los directorios administrados.
- Hotfix validado antes de repetir la prueba de failover de vaultwarden.
- F7 validada: la caída aislada de Vaultwarden mueve la VIP al siguiente nodo saludable y
  el retorno del contenedor recuperado devuelve la VIP al preferente.
- La prueba no modifica otros servicios y mantiene vaultwarden-2 fuera de la activación.
- La segunda instancia de laboratorio replicó hacia dos destinos con backup local.
- La VIP completó un relevo controlado de ida y vuelta y las pasadas repetidas devolvieron
  `sin_cambios`.
- Ambas instancias permanecen activas sin asumir nombres, volúmenes ni preferencias fijas.

## 0.5.0 — deduplicación de réplicas activas F6.2

- El receptor calcula una huella del contenido y no vuelve a parar el contenedor si ya aplicó la misma réplica.
- La huella aplicada se persiste en el estado del Guardian para sobrevivir a reinicios.
- La recepción activa requiere que los volúmenes de datos estén montados en modo escritura; observe y dry-run siguen sin modificar datos.
- Se mantiene `vaultwarden-2` deshabilitado mientras se valida la primera réplica activa.

## 0.4.0 — activación por instancia F6.1

- Cada instancia tiene una puerta `replication_enabled`, desactivada por defecto para configuraciones existentes.
- El panel permite activar una instancia de forma explícita y muestra su estado de replicación.
- El motor bloquea tanto el envío como la recepción si la instancia no está habilitada.
- Se mantiene `VG_MODE=observe` en producción; esta versión no activa la escritura automática.

## 0.3.0 — configuración operativa F1.2

- Alta, edición y borrado de instancias desde el panel y la API autenticada.
- El token administrativo se configura desde la plantilla y sólo vive en memoria de la interfaz.
- Descubrimiento de directorios únicamente dentro de las raíces montadas por el usuario.
- Validación de ruta de datos, contenedor Docker, endpoint de salud y Floating IP.
- Escritura atómica de instances.json y comprobación de identificadores, contenedores y servicios únicos.
- La plantilla generalista deja de asumir una instalación concreta y exige token administrativo.
- Se mantiene observe como modo seguro; esta fase no activa ni despliega la replicación.

## 0.2.0 — panel inicial y arranque genérico

- Panel web inicial servido por el propio contenedor.
- Primer arranque válido sin instancias prefijadas: muestra el estado de configuración
  pendiente en lugar de inventar una instalación.
- La imagen deja de depender de los nombres de las dos instancias actuales.
- Publicación preparada para recibir un destino explícito, sin registro local implícito.

## 0.1.0 — fase inicial

- Primer contrato de inventario de varias instancias Vaultwarden.
- Contrato inicial de API y de paquetes de réplica.
- Motor de snapshot SQLite consistente y recepción segura en modo explícito.
- Modo observe por defecto: no detiene contenedores ni escribe en sus datos.
