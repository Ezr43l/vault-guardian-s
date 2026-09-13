# Checklist pública de Vault Guardian 1.0.19

Una etiqueta pública sólo se crea cuando todas las puertas aplicables tienen evidencia.

## Código y suministro

- [ ] `VERSION`, plantilla, Compose, imagen y tag coinciden en `1.0.19`.
- [ ] GHCR publica exclusivamente `:1.0.19`; no se crean ni sobrescriben alias
  `:latest`, `:1` o `:1.0`.
- [ ] Apache-2.0 está presente y los metadatos OCI declaran la misma licencia.
- [ ] El snapshot público no contiene historial privado, `.env`, secretos, inventarios ni
  identificadores de infraestructura del autor.
- [ ] CI correcta sobre el SHA exacto del tag anotado.
- [ ] La protección **Immutable releases** está habilitada en el repositorio antes de
  crear el tag; el workflow debe montar un draft, verificar los cuatro assets y publicarlo
  al final. Un draft parcial es recuperable, pero una release publicada nunca se reabre.
- [ ] La puerta externa comprueba `GET /repos/{owner}/{repo}/immutable-releases` con una
  credencial administrativa efímera, obtiene `enabled=true` y sólo entonces fija la
  variable no secreta `IMMUTABLE_RELEASES_ENABLED=true`. Actions no almacena un PAT de
  administración; el workflow exige esa afirmación antes del primer push OCI y vuelve a
  comprobar la poscondición `immutable=true` después de publicar.
- [ ] Dependencias fijadas; `pip-audit`, Bandit y Gitleaks sin hallazgos aceptados en silencio.
- [ ] Builds Linux AMD64 y ARM64; Trivy sin HIGH/CRITICAL antes y después de publicar.
- [ ] SBOM SPDX, sumas, digest multi-arquitectura y attestation adjuntos a GitHub Release;
  la API confirma `immutable=true` y nombres, tamaños y SHA-256 exactos tras publicar.

## Producto completo

- [ ] Pasan todas las pruebas de portal, login, usuarios, TOTP, CSRF y UI.
- [ ] Pasan snapshot, linaje, antirreplay, conflicto, backup, restore y rollback.
- [ ] Pasan provisioning y reconciliación sin perder las funciones de 1.0.19.
- [ ] El laboratorio demuestra un único contenedor y un único montaje de `docker.sock`.
- [ ] La integración Docker rechaza contenedores, imágenes, rutas, privilegios y archivos ajenos.
- [ ] Primera cuenta y asistente funcionan con un inventario vacío.
- [ ] La plantilla Unraid contiene exactamente cuatro campos: puerto, estado,
  raíz de datos Vaultwarden y socket; no contiene secretos ni datos de topología.
- [ ] Un grupo nuevo genera su secreto; otro nodo puede adoptar el código durante
  el alta sin que éste aparezca en la plantilla ni en respuestas ordinarias.
- [ ] Vault Guardian reserva y libera una VIP contra Keepalived `0.14.1` y una
  repetición con la misma clave no consume una segunda dirección.

## Entorno externo

- [ ] Pull anónimo de `ghcr.io/ezr43l/vault-guardian-s:1.0.19` con un Docker config vacío.
- [ ] La URL raw de la única plantilla responde sin autenticación.
- [ ] Instalación limpia desde Compose y desde la única plantilla Unraid.
- [ ] HTTPS/CA privada, backup y restore reales.
- [ ] Tres hosts: sincronización, nodo atrasado, reconciliación, failover, conflicto y rollback.
- [ ] VRRP/ARP y firewall comprobados en hosts físicos; no se simula split-brain destructivo
  sobre un servicio de producción.

La línea privada continúa en `1.0.19` mientras se prepara la exportación. Los tags históricos
no se mueven; el repositorio público recibe `v1.0.19` una vez superadas estas
puertas.
