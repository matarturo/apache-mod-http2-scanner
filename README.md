# apache-mod-http2-scanner

Script NSE de Nmap, **no intrusivo**, para identificar de forma remota (por IP o dominio) servidores Apache HTTP Server potencialmente afectados por **CVE-2026-119618** (`mod_http2`, función `assign_headers()`).

**Versión:** 1.0.1 · **Autor:** Arturo E. Mata <arturo.mata@gmail.com> · **Licencia:** Apache-2.0

> ⚠️ **Aviso de verificación:** los rangos de versiones y los criterios de detección provienen **únicamente del boletín interno** (publicado el 11/11/2026); el CVE no pudo verificarse de forma independiente. Confírmalos contra el aviso oficial de Apache (<https://httpd.apache.org/security/vulnerabilities_24.html>) antes de usar los resultados en producción.

---

## Resumen de la vulnerabilidad (según el boletín)

| Campo | Valor |
|---|---|
| CVE | CVE-2026-119618 |
| Componente | Apache HTTP Server `mod_http2` |
| Causa | Sincronización inadecuada de recursos compartidos en `assign_headers()` |
| Impacto | Corrupción de memoria y ejecución remota de código |
| Severidad | Crítica, CVSS 9.8 |
| Afectados | Apache httpd 2.4.55 a 2.4.70; mod_h2 (GitHub) 2.0.8 a 2.0.42 |
| Corregido en | Apache httpd 2.4.71 o superior |
| Vector | Servidores con HTTP/2 (`h2` o `h2c`) habilitado mediante la directiva `Protocols` |

## Cómo funciona

El script **no explota nada ni envía payloads**. Hace tres cosas:

1. **Identifica el servidor** (`nmap -sV` o cabecera `Server`). Si no es Apache httpd (Tomcat, nginx, Traffic Server, etc.), termina sin más sondas.
2. **Comprueba HTTP/2:**
   - **h2:** negociación ALPN en un handshake TLS.
   - **h2c:** petición `Upgrade: h2c` en texto plano (espera `101 Switching Protocols`).
   - Si Nmap sabe que el puerto es TLS usa ALPN; si sabe que es texto plano usa h2c; **si no lo sabe, prueba h2c y, si no concluye, ALPN**.
3. **Compara la versión** con el rango afectado y emite el veredicto.

### Tabla de decisión

| Versión | HTTP/2 | Resultado |
|---|---|---|
| En rango | Activo | `VULNERABLE` |
| En rango | No detectado (comprobación concluyente) | `NOT VULNERABLE` |
| En rango | No se pudo comprobar | `NO CONCLUYENTE` |
| Fuera de rango | Cualquiera | `NOT VULNERABLE` |
| Oculta (`ServerTokens Prod`) | Activo | `LIKELY VULNERABLE` (o `NO CONCLUYENTE` con `hidden_version=unknown`) |
| Oculta | No detectado (concluyente) | `NOT VULNERABLE` |
| Oculta | No se pudo comprobar | `NO CONCLUYENTE` |
| No es Apache httpd | — | Sin salida (nota con `vulns.showall`) |

## Requisitos

- Nmap 7.x o superior (librerías `http`, `tls`, `vulns`).
- Autorización para escanear el objetivo.

## Instalación

```bash
sudo cp apache-mod-http2-scanner.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
nmap --script-help apache-mod-http2-scanner      # verificar
```

macOS (Homebrew): `/opt/homebrew/share/nmap/scripts/` · Windows: `C:\Program Files (x86)\Nmap\scripts\`

También puedes ejecutarlo sin instalar: `nmap --script ./apache-mod-http2-scanner.nse ...`

## Uso rápido

```bash
# Por IP
nmap -p 80,443,8080,8443 --script apache-mod-http2-scanner 192.168.1.10

# Por dominio (solo el hostname, sin https://)
nmap -p 80,443 --script apache-mod-http2-scanner ejemplo.com

# Con detección de servicio (recomendado: mejora versión y puertos no estándar)
nmap -sV -p 80,443 --script apache-mod-http2-scanner ejemplo.com

# Ver también los resultados negativos
nmap -sV -p 80,443 --script apache-mod-http2-scanner --script-args vulns.showall ejemplo.com

# Rango de red
nmap -p 80,443 --script apache-mod-http2-scanner 10.0.0.0/24
```

## Argumentos

| Argumento | Descripción | Defecto |
|---|---|---|
| `apache-mod-http2-scanner.path` | Ruta HTTP a consultar | `/` |
| `apache-mod-http2-scanner.min` | Versión mínima afectada | `2.4.55` |
| `apache-mod-http2-scanner.max` | Versión máxima afectada | `2.4.70` |
| `apache-mod-http2-scanner.timeout` | Timeout de sockets (ms) | `5000` |
| `apache-mod-http2-scanner.ssl` | `true` fuerza ALPN, `false` fuerza h2c | automático |
| `apache-mod-http2-scanner.hidden_version` | `likely` o `unknown`: tratamiento de Apache con HTTP/2 y versión oculta | `likely` |
| `http.useragent` | User-Agent de las peticiones HTTP (incluida la h2c) | `Nmap NSE` |
| `vulns.showall` | Muestra también `NOT VULNERABLE` y notas informativas | — |

## Interpretación de resultados

| Estado | Significado | Acción |
|---|---|---|
| `VULNERABLE` | Versión en rango y HTTP/2 activo | Verificar localmente y mitigar |
| `LIKELY VULNERABLE` | Apache con HTTP/2, versión oculta | Verificar con `httpd -v` en el servidor |
| `NO CONCLUYENTE` | No se pudo completar alguna comprobación | Reintentar con `-sV`, otro `timeout`, o verificar localmente |
| `NOT VULNERABLE` | Fuera de rango, o HTTP/2 no detectado | Ninguna para este CVE (solo visible con `vulns.showall`) |

`NO CONCLUYENTE` se muestra **aparte**, sin el encabezado `VULNERABLE:`, para no confundirlo con un positivo.

Salida de ejemplo:

```
PORT     STATE SERVICE  VERSION
8443/tcp open  ssl/http Apache httpd 2.4.70 ((Unix) OpenSSL/3.5.7)
| apache-mod-http2-scanner:
|   VULNERABLE:
|   Apache HTTP Server mod_http2 - corrupcion de memoria / RCE (severidad Critica)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2026-119618
|     Risk factor: High  CVSSv3: 9.8
|     Check results:
|       Banner/Version: Apache/2.4.70 (nmap -sV)
|       HTTP/2 habilitado: SI - h2 (ALPN)
|       Rango afectado: 2.4.55 - 2.4.70 (corregido en 2.4.71)
|_      Script: apache-mod-http2-scanner v1.0.1
```

> `Risk factor: High`: la librería `vulns` de Nmap solo admite High/Medium/Low. La severidad real (Crítica, CVSS 9.8) figura en el título y en el campo CVSSv3.

## Proxy y User-Agent

- **`--proxies`**: solo si tu red sale por un proxy o el alcance lo exige. Requiere `-sT` y `-Pn`, y conviene subir `timeout` a 10000 o más.

  ```bash
  nmap -sT -Pn -p 443 --proxies socks4://127.0.0.1:9050 \
    --script apache-mod-http2-scanner \
    --script-args apache-mod-http2-scanner.timeout=10000 ejemplo.com
  ```

- **User-Agent**: la prueba ALPN no envía HTTP, por lo que no lo usa. `http.useragent` afecta a la lectura de la cabecera `Server` y a la petición h2c. En escaneos corporativos conviene un valor honesto e identificable:

  ```bash
  --script-args 'http.useragent=SecScan-InternoTI'
  ```

## Limitaciones

- **Backports de distribuciones** (Debian, Ubuntu, RHEL…): pueden corregir la falla sin cambiar la versión visible, lo que produce falsos positivos.
- **`ServerTokens Prod`** oculta la versión: resultado `LIKELY VULNERABLE` o `NO CONCLUYENTE`.
- **mod_h2 de GitHub (2.0.8 a 2.0.42)** no se puede identificar remotamente.
- **CDN o proxy inverso** puede negociar HTTP/2 por su cuenta sin que el backend Apache lo use.
- **TLS 1.3 exclusivo:** la sonda ALPN usa un ClientHello TLS 1.2; un servidor que solo acepte TLS 1.3 produce `NO CONCLUYENTE`.
- **Puertos no estándar:** el script se activa por servicio HTTP/HTTPS o puertos habituales (80, 443, 8080, 8443, 8000, 8088, 8180…). En otros puertos usa `-sV`.
- Un WAF o IPS puede bloquear las sondas y provocar resultados negativos o no concluyentes.

## Pruebas realizadas

| Caso | Resultado |
|---|---|
| h2c en texto plano | VULNERABLE ✅ |
| h2 con TLS (ALPN) | VULNERABLE ✅ |
| h2 con TLS en puerto que Nmap no reconoce como TLS (respaldo ALPN) | VULNERABLE ✅ |
| Solo HTTP/1.1, texto plano y TLS | NOT VULNERABLE ✅ |
| Versión fuera de rango (`min`/`max`) | NOT VULNERABLE ✅ |
| Versión oculta + h2/h2c | LIKELY VULNERABLE ✅ (y NO CONCLUYENTE con `hidden_version=unknown`) |
| Versión oculta + solo HTTP/1.1 | NOT VULNERABLE ✅ |
| TLS 1.3 exclusivo | NO CONCLUYENTE ✅ |
| `Apache-Coyote` (Tomcat) y servidor Python | Sin salida / "No aplica" ✅ |
| Argumentos `ssl`, `hidden_version` (válidos e inválidos), `http.useragent`, puerto cerrado | ✅ |

Entornos: laboratorio con Apache 2.4.58 (Ubuntu) y Nmap 7.94; y, con resultados aportados por el autor, Docker `httpd:2.4.70` con Nmap 7.95 (h2c y h2 sobre TLS).

**Sin probar:** objetivos IPv6, una versión corregida real (2.4.71) y mod_h2 independiente de GitHub. Estas pruebas validan la lógica de detección contra el rango del boletín; **no demuestran** que una versión concreta sea explotable.

El directorio [`tests/`](tests/) incluye un laboratorio Docker reproducible.

## Mitigación (según el boletín)

1. Actualizar Apache HTTP Server a **2.4.71 o superior**, o aplicar los parches de la distribución, primero en un ambiente controlado.
2. Si no es posible actualizar de inmediato, **deshabilitar HTTP/2** quitando `h2` y `h2c` de la directiva `Protocols`:

   ```apache
   Protocols http/1.1
   ```

   Después: `apachectl configtest && apachectl graceful`.
3. Priorizar los sistemas expuestos a Internet con HTTP/2 habilitado. Las configuraciones solo HTTP/1.1 no requieren medidas de emergencia para esta vulnerabilidad.

## Uso responsable

Usa este script **únicamente contra sistemas propios o con autorización escrita**. Escanear sistemas ajenos sin permiso puede ser ilegal.

## Licencia

Copyright 2026 Arturo E. Mata. Distribuido bajo la **Apache License, Version 2.0** (ver [`LICENSE`](LICENSE)). El software se entrega "TAL CUAL", sin garantías de ningún tipo.
