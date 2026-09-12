# Inventario de Vaultwarden

El repositorio no incluye un inventario real. Cada instalación lo crea desde el portal o en
`/state/instances.json`; nunca se debe publicar ese fichero ni copiarlo entre nodos sin revisar
las rutas locales.

Por cada instancia registra fuera del repositorio:

| Campo | Ejemplo documental | Regla |
|---|---|---|
| ID | `primary-vault` | Único y estable en el grupo |
| Contenedor | `vaultwarden-primary` | Imagen oficial Vaultwarden |
| Puerto de salud | `8080` | Libre y equivalente en los destinos |
| Ruta de salud | `/alive` | Ruta HTTP relativa, sin URL completa |
| Servicio flotante | `primary-vault` | Debe existir en floating-ip |
| Backend de datos | `auto` | Resuelve el bind `/data` dentro de la raíz montada |
| Ruta host de origen | elegida por el operador | Un único bind en `/data` |

Los ejemplos públicos utilizan nombres ficticios y direcciones reservadas para documentación.
No copies nombres de ejemplo como una convención obligatoria.

## Preflight obligatorio

Antes de crear una réplica, Guardian debe confirmar:

- imagen oficial fijada por digest;
- destino dentro de la raíz autorizada del host;
- nombre, puerto y carpeta sin colisiones;
- ausencia de `privileged`, host network, dispositivos y montajes adicionales;
- usuario de contenedor por defecto de la imagen oficial (root); la versión 1.0.18 rechaza
  `Config.User` personalizado porque no puede preservar su UID/GID y permisos de `/data`
  de forma segura en todos los hosts;
- conectividad con todos los Guardian y con floating-ip;
- snapshot válido y destino vacío.

El inventario público sólo describe el esquema. Tokens, variables de entorno completas,
direcciones internas y rutas reales pertenecen al almacén privado de cada despliegue.
