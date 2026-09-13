# Instalación reproducible de Vault Guardian 1.0.19

Vault Guardian se instala en servidores Docker Linux `amd64` o `arm64` como una
sola aplicación y un único contenedor permanente. La plantilla descarga una
imagen ya construida; no necesita el repositorio privado ni un registro local.

## Requisitos

```bash
docker version
docker compose version
docker info --format '{{.OSType}}/{{.Architecture}}'
```

El operador debe poder montar `/var/run/docker.sock` y una raíz host que contenga los
bind mounts `/data` de Vaultwarden. Ese socket concede control
equivalente al daemon Docker: no lo publiques por TCP y restringe el portal con
HTTPS, VPN o firewall.

## Docker Compose

```bash
cp .env.example .env
install -d -m 0700 local-data/state
docker compose --env-file .env config --quiet
test "$(docker compose --env-file .env config --services | wc -l)" -eq 1
docker compose --env-file .env pull
docker compose --env-file .env up -d
curl --fail http://127.0.0.1:6062/api/health
```

`.env` sólo decide la imagen, el estado, la raíz de datos y la publicación del puerto. El resto,
incluido HTTPS o HTTP aislado, se solicita en el portal. La aplicación genera y conserva
su secreto local bajo `/state/secrets`; no hay que crear tres ficheros antes de
arrancar.

## Unraid

1. Crea el directorio persistente:

   ```bash
   install -d -m 0700 -o root -g root /mnt/user/appdata/vault-guardian
   ```

2. Importa únicamente `unraid/my-Vault-Guardian.xml`.
3. Revisa puerto, estado, raíz de datos Vaultwarden y socket Docker. Al abrir el portal podrás
   elegir si el alta llegará por HTTP aislado o por HTTPS.
4. Aplica y comprueba que sólo existe un contenedor `Vault-Guardian`.

No se necesita un contenedor Docker Control, una red auxiliar ni montajes de
secretos.

## Configuración dentro de la aplicación

1. Crea la primera cuenta y una contraseña propia.
2. Para un grupo nuevo, deja vacío **Código de un grupo existente**. Para añadir
   un nodo, copia el código desde un Guardian ya configurado y pégalo durante el
   alta de la primera cuenta.
3. En **Grupo**, define nombre, IP, URL de cada Guardian y endpoint de Keepalived.
4. Copia el token de integración generado por Keepalived e introdúcelo en
   **Conexión con Keepalived**. Vault Guardian lo guarda localmente y nunca lo
   devuelve en la API de configuración.
5. Registra o aprovisiona Vaultwarden y valida su readiness. Sólo al crear réplicas,
   indica la ruta host completa de cada destino; Guardian utiliza una carpeta vacía
   existente o crea la carpeta final si todavía no existe.
6. En **Ajustes de la aplicación**, revisa la duración de sesión, el historial y el
   acceso HTTP/HTTPS. Configura el token API o una CA privada sólo si los necesitas.
7. Activa TOTP y pasa de `observe` a `active` sólo después de comprobar todos los
   nodos.

El endpoint local predeterminado es
`http://host.docker.internal:6060`. Compose y la plantilla añaden el gateway del
host de forma técnica; no es una dirección del entorno del autor. Un endpoint
remoto HTTP sigue requiriendo la aceptación explícita en **Grupo > Permitir HTTP
interno**; para otros servidores se recomienda HTTPS.

## Actualización desde 1.0.4

Conserva el volumen `/state` y la configuración vigente. Los montajes antiguos
de `replication-token`, `floating-api-token` y `api-token` siguen teniendo
precedencia si permanecen definidos, por lo que la migración no cambia secretos
silenciosamente. Para administrarlos desde el portal, retira esas variables y
copia previamente los valores al subdirectorio `/state/secrets` correspondiente.

Actualiza primero un nodo pasivo. Verifica salud, versión, cuenta, inventario y
conectividad con Keepalived antes de continuar con el siguiente.

## Compilar localmente

```bash
VG_IMAGE=vault-guardian:1.0.19 ./build-image.sh
```

El script sólo construye y prueba localmente. La publicación se realiza desde el
workflow del futuro repositorio público y usa un tag de versión inmutable.
