<p align="center">
  <img src="assets/github-banner.svg" alt="Vault Guardian — gestión y réplica de Vaultwarden" width="100%">
</p>

<p align="center">
  <img alt="Un contenedor" src="https://img.shields.io/badge/despliegue-1%20contenedor-55df9a">
  <img alt="Linux AMD64 y ARM64" src="https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-12cddd">
  <a href="LICENSE"><img alt="Licencia Apache 2.0" src="https://img.shields.io/badge/licencia-Apache--2.0-7d91a3"></a>
</p>

# Vault Guardian

Vault Guardian administra varias instancias de Vaultwarden desde un único portal. Permite
inventariarlas, crear nuevas réplicas, comprobar su estado y mantener sus datos alineados
entre varios servidores.

Se distribuye como un único contenedor para Linux `amd64` y `arm64`.

## Funciones principales

- Descubrimiento e inventario de instancias Vaultwarden.
- Aprovisionamiento de nuevas réplicas.
- Copias SQLite consistentes y respaldos antes de cada sustitución.
- Transporte cifrado entre nodos.
- Reconciliación de nodos incorporados posteriormente.
- Integración con Keepalived para localizar el nodo activo.
- Usuarios, sesiones y segundo factor TOTP.
- Una credencial API independiente por aplicación consumidora.

## Requisitos

- Docker Engine en cada servidor.
- Socket Docker local.
- Una raíz del host que contenga los datos de las instancias Vaultwarden.
- Un directorio persistente propio para Vault Guardian.
- Conectividad entre los nodos que formarán el grupo.

El acceso al socket Docker equivale a un acceso elevado al servidor. Limita el acceso al
portal y no publiques el socket por TCP.

## Instalación con Docker

Ajusta `/srv/vaultwarden` a la raíz que contiene los directorios de datos de tus
instancias:

```bash
sudo mkdir -p /srv/vault-guardian
sudo chmod 700 /srv/vault-guardian

sudo docker run -d \
  --name vault-guardian \
  --restart unless-stopped \
  --user 0:0 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --tmpfs /tmp:size=2g,mode=1777 \
  --add-host host.docker.internal:host-gateway \
  -p 6062:6062 \
  -v /srv/vault-guardian:/state \
  -v /srv/vaultwarden:/instances \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/ezr43l/vault-guardian-s:stable
```

Abre `http://SERVIDOR:6062`, crea la primera cuenta y completa la configuración del
grupo, Keepalived y las instancias.

También puedes usar [Docker Compose](compose.yaml), la
[guía de instalación](docs/installation.md) o la
[plantilla para Unraid](unraid/my-Vault-Guardian.xml).

## Datos de nuevas réplicas

Al crear una réplica, indica el directorio que utilizará Vaultwarden. Si la ruta ya existe,
Guardian la utiliza. Si no existe dentro de la raíz autorizada, la crea antes de desplegar
la instancia. Esta ruta sólo es obligatoria cuando se crea o se incorpora una réplica.

## Grupo y sincronización

Configura primero un nodo sin código de incorporación. Utiliza después el código generado
para unir los demás. Vault Guardian sólo acepta como origen al portador de la dirección
flotante confirmado por Keepalived.

Antes de sustituir datos en un nodo pasivo crea un respaldo local y valida el paquete
recibido. Si la autoridad no puede determinarse, la sincronización queda bloqueada.

## API

Cada integración dispone de nombre y credencial propios. Desde el portal puedes crear,
renovar o revocar cada acceso por separado.

Referencia:

- [API](docs/api.md)
- [Contrato de réplica](docs/replication-contract.md)
- [Arquitectura](docs/architecture.md)
- [Seguridad](docs/security.md)
- [Operación y recuperación](docs/operations.md)

## Soporte

El soporte se presta en la comunidad de Discord de Unraides:

https://discord.gg/8MAT6ZGJTW

No compartas contraseñas, tokens, datos de Vaultwarden ni registros privados.

## Licencia

Código y documentación: [Apache License 2.0](LICENSE).

