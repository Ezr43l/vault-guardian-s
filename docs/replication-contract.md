# Contrato de replicación

## Paquete

El cuerpo de la réplica es un fichero cifrado con el token de replicación. Al descifrarlo
contiene un `tar.gz` con esta forma:

```text
manifest.json
data/db.sqlite3
data/config.json                 # si existe
data/rsa_key*                    # los que existan
data/attachments/**
data/sends/**
```

No entran `db.sqlite3-wal`, `db.sqlite3-shm`, `icon_cache`, logs ni `tmp`. El manifiesto
incluye formato, instancia, nodo origen, fecha, hash de base de datos y listado de
ficheros con tamaño y hash.

## Producción

Vaultwarden recomienda el Online Backup API de SQLite para una base en uso. Guardian usa
`sqlite3.Connection.backup()` desde el host del contenedor Guardian, que evita depender de
`docker exec` y produce una base autónoma. El volumen fuente no se modifica.

## Aplicación

El receptor:

1. comprueba token, tamaño y formato;
2. valida que no hay rutas absolutas ni `..` y que los enlaces quedan dentro del paquete;
3. vuelve a preguntar a `floating-ip` quién sostiene el servicio;
4. rechaza si el receptor es el activo o si el origen ya no es el portador;
5. inspecciona que existe el contenedor de esa instancia;
6. detiene sólo ese contenedor;
7. guarda un backup local;
8. reemplaza base, adjuntos, Sends y claves;
9. arranca el contenedor en un bloque `finally`;
10. comprueba salud y registra el resultado sin incluir datos.

Si el estado local y el remoto tienen cambios distintos, la sincronización normal no
decide por fuerza bruta. Se conserva el backup y se requiere una operación explícita de
resolución.

