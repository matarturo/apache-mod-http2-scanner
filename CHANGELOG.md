# Changelog

## 1.0.1

### Corregido
- `risk_factor` inválido (`Critical`): la librería `vulns` solo admite High/Medium/Low y descartaba el reporte en silencio. Ahora usa `High`; la severidad crítica y el CVSS 9.8 figuran en el título y en CVSSv3.
- Puerto TLS que Nmap no reconoce como TLS: antes solo se probaba h2c (falso negativo). Ahora, en modo automático, se prueba h2c y, si no concluye, ALPN.
- Un resultado no concluyente ya no aparece bajo el encabezado `VULNERABLE:`.
- Apache con versión oculta y sin HTTP/2 ahora da `NOT VULNERABLE` (la ruta vulnerable no está expuesta) en lugar de `UNKNOWN`.

### Añadido
- Argumento `ssl` (`true`/`false`) para forzar ALPN o h2c.
- Argumento `hidden_version` (`likely`/`unknown`).
- Soporte de `http.useragent` también en la petición h2c.
- Trazas `stdnse.debug` en conexión, envío, lectura y parseo.
- Cabecera `Host:` con puerto cuando no es el 80 y corchetes para IPv6 literal.
- Identificación estricta de Apache httpd (excluye Tomcat/Coyote, Traffic Server y otros productos "Apache ...").
- Sin sondas adicionales ni salida cuando el servidor no es Apache httpd (nota con `vulns.showall`).
- `LICENSE` (Apache-2.0), `CHANGELOG.md` y laboratorio Docker en `tests/`.

## 1.0.0
- Versión inicial: detección por versión (2.4.55–2.4.70) y HTTP/2 (h2 por ALPN, h2c por Upgrade).
