# Política de seguridad

## Versiones compatibles

La línea mantenida actualmente es `1.0.x`. Las correcciones se desarrollan primero en el
repositorio privado y se publican en el repositorio compartido cuando existe una release
validada.

## Comunicar una vulnerabilidad

Utiliza **Security > Report a vulnerability** en este repositorio compartido para abrir un
aviso privado de GitHub. No abras un issue con tokens, paquetes `.vgb`, bases de datos,
inventarios, logs con direcciones privadas o capturas del portal autenticado.

Incluye la versión, arquitectura, configuración mínima anonimizada, impacto, pasos de
reproducción y si se ha probado contra el digest publicado. Se acusará recibo antes de hacer
públicos detalles que faciliten explotación.

## Modelo de privilegios

- La aplicación se ejecuta en un único contenedor con filesystem de sólo lectura,
  capabilities eliminadas y `no-new-privileges`.
- El contenedor monta el socket Docker local y por ello usa UID/GID `0:0`. El socket concede
  autoridad equivalente a la del daemon: no debe publicarse por TCP y el acceso al host y
  al panel debe quedar restringido.
- Guardian valida que cada bind `/data` pertenece a la raíz host montada en `/instances`;
  no crea contenedores auxiliares para leer o aplicar datos.
- HTTPS es el valor seguro para pares y floating-ip. HTTP requiere aceptación explícita y una
  red aislada.
- Los secretos técnicos son independientes y no tienen valores compartidos por
  defecto. Los nuevos despliegues los generan o solicitan desde la aplicación y
  los conservan en el volumen privado; la plantilla no contiene sus rutas.

Una persona con control del daemon Docker o del host ya puede superar el aislamiento de los
contenedores; ese riesgo queda fuera del límite de confianza de Guardian y debe mitigarse con
acceso administrativo mínimo, backups y auditoría del host.
