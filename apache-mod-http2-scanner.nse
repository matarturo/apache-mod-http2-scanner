-- apache-mod-http2-scanner.nse
-- Version 1.0.1
-- Copyright 2026 Arturo E. Mata <arturo.mata@gmail.com>
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local shortport = require "shortport"
local stdnse    = require "stdnse"
local nmap      = require "nmap"
local http      = require "http"
local tls       = require "tls"
local vulns     = require "vulns"
local string    = require "string"
local table     = require "table"

local SCRIPT_VERSION = "1.0.1"

description = [[
Escaner no intrusivo para Apache HTTP Server con mod_http2 potencialmente
afectado por CVE-2026-119618 (assign_headers(), corrupcion de memoria / RCE).

Realiza dos comprobaciones:
  1. Version de Apache httpd (nmap -sV o cabecera Server) dentro del rango afectado.
  2. HTTP/2 habilitado: h2 (ALPN sobre TLS) o h2c (Upgrade en texto plano).
     Si Nmap no sabe si el puerto usa TLS, se prueban ambos metodos.

No envia exploits ni payloads. Limitaciones:
  - ServerTokens Prod oculta la version (resultado "probable" o "no concluyente").
  - Los backports de distribuciones pueden dar falsos positivos.
  - mod_h2 de GitHub (2.0.8-2.0.42) no es identificable remotamente.
  - Un CDN/proxy puede hablar HTTP/2 sin que el backend Apache lo haga.
  - La prueba ALPN usa un ClientHello TLS 1.2: servidores solo TLS 1.3 daran
    un resultado no concluyente.

Version del script: 1.0.1
Nota: el CVE no pudo verificarse de forma independiente; los rangos provienen
del boletin interno. Confirmelos contra el aviso oficial de Apache.
]]

---
-- @usage
-- nmap -p 80,443,8080,8443 --script apache-mod-http2-scanner <IP|dominio>
-- nmap -sV -p 80,443 --script apache-mod-http2-scanner <IP|dominio>
-- nmap -sV -p 9443 --script apache-mod-http2-scanner \
--   --script-args apache-mod-http2-scanner.ssl=true <IP|dominio>
--
-- @args apache-mod-http2-scanner.path            Ruta HTTP a consultar (default: /)
-- @args apache-mod-http2-scanner.min             Version minima afectada (default: 2.4.55)
-- @args apache-mod-http2-scanner.max             Version maxima afectada (default: 2.4.70)
-- @args apache-mod-http2-scanner.timeout         Timeout de sockets en ms (default: 5000)
-- @args apache-mod-http2-scanner.ssl             true/false: fuerza ALPN (true) o h2c (false).
--                                                Por defecto se detecta automaticamente.
-- @args apache-mod-http2-scanner.hidden_version  likely|unknown: como tratar Apache con
--                                                HTTP/2 activo y version oculta (default: likely)
-- @args http.useragent                           User-Agent para las peticiones HTTP
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | apache-mod-http2-scanner:
-- |   VULNERABLE:
-- |   Apache HTTP Server mod_http2 - corrupcion de memoria / RCE (severidad Critica)
-- |     State: VULNERABLE
-- |     IDs: CVE:CVE-2026-119618
-- |     Risk factor: High  CVSSv3: 9.8
-- |     Check results:
-- |       Banner/Version: Apache/2.4.62 (Debian)
-- |       HTTP/2 habilitado: SI - h2 (ALPN)
-- |       Rango afectado: 2.4.55 - 2.4.70 (corregido en 2.4.71)
-- |_      Script: apache-mod-http2-scanner v1.0.1

author = "Arturo E. Mata <arturo.mata@gmail.com>"
license = "Apache-2.0 - http://www.apache.org/licenses/LICENSE-2.0"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

---------------------------------------------------------------------------
-- Utilidades
---------------------------------------------------------------------------
local function to_version(s)
  if not s then return nil end
  local a, b, c = s:match("(%d+)%.(%d+)%.(%d+)")
  if a then return {tonumber(a), tonumber(b), tonumber(c)} end
  return nil
end

local function parse_apache(s)
  if not s then return nil end
  local a, b, c = s:match("Apache/(%d+)%.(%d+)%.(%d+)")
  if a then return {tonumber(a), tonumber(b), tonumber(c)} end
  return nil
end

local function cmp(v1, v2)
  for i = 1, 3 do
    if v1[i] < v2[i] then return -1 end
    if v1[i] > v2[i] then return 1 end
  end
  return 0
end

local function vstr(v) return table.concat(v, ".") end

local function parse_bool(v)
  if v == nil then return nil end
  v = tostring(v):lower()
  if v == "1" or v == "true" or v == "yes" then return true end
  if v == "0" or v == "false" or v == "no" then return false end
  return nil
end

-- Producto reportado por nmap -sV que corresponde a Apache httpd
-- (excluye Tomcat, Traffic Server y otros productos "Apache ...").
local function is_httpd_product(prod)
  if not prod then return false end
  prod = prod:lower()
  return prod == "apache httpd" or prod == "apache" or prod == "httpd"
end

-- Cabecera Server que corresponde a Apache httpd.
local function is_httpd_banner(server)
  if not server then return false end
  if server:find("Tomcat") or server:find("Coyote") or server:find("Traffic") then
    return false
  end
  return server:match("^Apache$") ~= nil
      or server:match("^Apache/") ~= nil
      or server:match("^Apache%s") ~= nil
end

---------------------------------------------------------------------------
-- Identificacion del servidor
-- Devuelve {is_apache = true|false|nil, version = {x,y,z}|nil, banner = str|nil}
---------------------------------------------------------------------------
local function identify_server(host, port, path, scheme)
  local res = {is_apache = nil, version = nil, banner = nil}

  local pv = port.version
  if pv and pv.product then
    if is_httpd_product(pv.product) then
      res.is_apache = true
      res.version = to_version(pv.version)
      res.banner = res.version and ("Apache/" .. vstr(res.version) .. " (nmap -sV)")
                                or "Apache httpd (nmap -sV, version oculta)"
    else
      res.is_apache = false
      res.banner = pv.product .. (pv.version and (" " .. pv.version) or "") .. " (nmap -sV)"
    end
    stdnse.debug1("identify: producto de -sV = %s", res.banner)
    return res
  end

  local opts = scheme and {scheme = scheme} or nil
  local resp = http.head(host, port, path, opts)
  if not (resp and resp.header and resp.header.server) then
    resp = http.get(host, port, path, opts)
  end
  if resp and resp.header and resp.header.server then
    local server = resp.header.server
    res.banner = server
    if is_httpd_banner(server) then
      res.is_apache = true
      res.version = parse_apache(server)
    else
      res.is_apache = false
    end
    stdnse.debug1("identify: cabecera Server = %s (apache=%s)", server, tostring(res.is_apache))
  else
    stdnse.debug1("identify: sin cabecera Server (scheme=%s)", tostring(scheme))
  end
  return res
end

---------------------------------------------------------------------------
-- h2 via ALPN (TLS)
-- Devuelve: tls_ok (se recibio ServerHello), h2 (el servidor eligio "h2")
---------------------------------------------------------------------------
local function probe_alpn(host, port, timeout)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout)
  local ok, err = sock:connect(host, port)
  if not ok then
    stdnse.debug1("ALPN: fallo al conectar: %s", tostring(err))
    sock:close()
    return false, false
  end

  local hello = tls.client_hello({
    protocol = "TLSv1.2",
    ciphers = {
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_128_GCM_SHA256",
    },
    extensions = {
      ["application_layer_protocol_negotiation"] =
        tls.EXTENSION_HELPERS["application_layer_protocol_negotiation"]({"h2", "http/1.1"}),
    },
  })

  if not sock:send(hello) then
    stdnse.debug1("ALPN: fallo al enviar ClientHello")
    sock:close()
    return false, false
  end

  local buffer, pos = "", 1
  for _ = 1, 10 do
    local rok, data = sock:receive_bytes(1)
    if not rok then
      stdnse.debug2("ALPN: lectura terminada: %s", tostring(data))
      break
    end
    buffer = buffer .. data

    local p_ok, new_pos, record = pcall(tls.record_read, buffer, pos)
    if p_ok and new_pos and record then
      pos = new_pos
      if record.type == "alert" then
        stdnse.debug1("ALPN: el servidor respondio con una alerta TLS")
        sock:close()
        return false, false
      end
      for _, body in ipairs(record.body or {}) do
        if body.type == "server_hello" then
          sock:close()
          local ext = body.extensions
            and body.extensions["application_layer_protocol_negotiation"]
          if not ext then
            stdnse.debug1("ALPN: ServerHello sin extension ALPN")
            return true, false
          end
          -- Formato: 2 bytes longitud de lista + (1 byte longitud + protocolo)
          local ok1, list = pcall(string.unpack, ">s2", ext)
          if ok1 and list then
            local ok2, proto = pcall(string.unpack, "s1", list)
            stdnse.debug1("ALPN: protocolo elegido = %s", tostring(proto))
            return true, (ok2 and proto == "h2")
          end
          return true, false
        end
      end
    end
  end
  sock:close()
  return false, false
end

---------------------------------------------------------------------------
-- h2c via Upgrade (texto plano)
-- Devuelve: plain_ok (HTTP en claro respondio, distinto de 400), h2 (101)
---------------------------------------------------------------------------
local function probe_h2c(host, port, path, timeout)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout)
  local ok, err = sock:connect(host, port)
  if not ok then
    stdnse.debug1("h2c: fallo al conectar: %s", tostring(err))
    sock:close()
    return false, false
  end

  local hostname = host.targetname
  if not hostname then
    hostname = host.ip
    if hostname:find(":") then hostname = "[" .. hostname .. "]" end
  end
  if port.number ~= 80 then hostname = hostname .. ":" .. port.number end

  local ua = stdnse.get_script_args("http.useragent") or "Nmap NSE"
  ua = ua:gsub("[\r\n]", " ")

  local req = table.concat({
    "GET " .. path .. " HTTP/1.1",
    "Host: " .. hostname,
    "Connection: Upgrade, HTTP2-Settings",
    "Upgrade: h2c",
    "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA",
    "User-Agent: " .. ua,
    "", ""
  }, "\r\n")

  if not sock:send(req) then
    stdnse.debug1("h2c: fallo al enviar la peticion")
    sock:close()
    return false, false
  end

  local rok, data = sock:receive_bytes(12)
  sock:close()
  if not (rok and data) then
    stdnse.debug1("h2c: sin respuesta")
    return false, false
  end

  local status = data:match("^HTTP/1%.[01]%s+(%d+)")
  stdnse.debug1("h2c: estado HTTP = %s", tostring(status))
  if not status then return false, false end
  return status ~= "400", status == "101"
end

---------------------------------------------------------------------------
-- Accion principal
---------------------------------------------------------------------------
action = function(host, port)
  local args    = SCRIPT_NAME
  local path    = stdnse.get_script_args(args .. ".path") or "/"
  local timeout = tonumber(stdnse.get_script_args(args .. ".timeout")) or 5000
  local min_v   = to_version(stdnse.get_script_args(args .. ".min") or "2.4.55")
  local max_v   = to_version(stdnse.get_script_args(args .. ".max") or "2.4.70")
  local forced  = parse_bool(stdnse.get_script_args(args .. ".ssl"))
  local hidden  = (stdnse.get_script_args(args .. ".hidden_version") or "likely"):lower()
  local showall = stdnse.get_script_args("vulns.showall") or stdnse.get_script_args("vuln.showall")
  local verbose = showall ~= nil  -- mensajes informativos solo con vulns.showall

  if not (min_v and max_v) then
    return "Error: formato invalido en argumentos min/max (use X.Y.Z)."
  end
  if hidden ~= "likely" and hidden ~= "unknown" then
    return "Error: hidden_version debe ser 'likely' o 'unknown'."
  end

  local ssl_known = shortport.ssl(host, port)
    or (port.version and port.version.service_tunnel == "ssl")

  -- 1. Identificar el servidor (sin sondas adicionales si no es Apache httpd)
  local srv = identify_server(host, port, path, nil)
  if srv.is_apache == false then
    if verbose then
      return ("No aplica: servidor no identificado como Apache httpd (%s)."):format(srv.banner or "?")
    end
    return nil
  end

  -- 2. Comprobar HTTP/2
  local h2, mode, conclusive, tls_detected = false, nil, false, false
  local mode_sel = (forced == true and "tls") or (forced == false and "plain")
                   or (ssl_known and "tls") or "auto"
  stdnse.debug1("modo de sondeo: %s", mode_sel)

  if mode_sel == "plain" or mode_sel == "auto" then
    local plain_ok, h2c = probe_h2c(host, port, path, timeout)
    if h2c then
      h2, mode, conclusive = true, "h2c (Upgrade)", true
    elseif plain_ok then
      conclusive = true
    end
  end
  if not h2 and (mode_sel == "tls" or (mode_sel == "auto" and not conclusive)) then
    local tls_ok, alpn_h2 = probe_alpn(host, port, timeout)
    if tls_ok then tls_detected, conclusive = true, true end
    if alpn_h2 then h2, mode = true, "h2 (ALPN)" end
  end
  if mode_sel == "tls" then tls_detected = true end

  -- 3. Si no hubo cabecera Server y se detecto TLS, reintentar por https
  if srv.is_apache == nil and tls_detected and not ssl_known then
    srv = identify_server(host, port, path, "https")
  end

  if srv.is_apache == nil then
    if verbose then
      return "No concluyente: no se pudo identificar el servidor (sin cabecera Server)."
    end
    return nil
  end

  -- 4. Veredicto
  local out = {
    "Banner/Version: " .. (srv.banner or "no disponible"),
    "HTTP/2 habilitado: " .. (h2 and ("SI - " .. mode) or "NO detectado"),
    ("Rango afectado: %s - %s (corregido en 2.4.71)"):format(vstr(min_v), vstr(max_v)),
    "Script: " .. SCRIPT_NAME .. " v" .. SCRIPT_VERSION,
  }

  local state, inconclusive_reason
  if srv.version then
    local affected = cmp(srv.version, min_v) >= 0 and cmp(srv.version, max_v) <= 0
    if not affected then
      state = vulns.STATE.NOT_VULN
    elseif h2 then
      state = vulns.STATE.VULN
    elseif conclusive then
      state = vulns.STATE.NOT_VULN
      out[#out + 1] = "Version afectada, pero HTTP/2 no detectado: verifique la directiva Protocols."
    else
      inconclusive_reason = "Version afectada, pero no se pudo comprobar HTTP/2 (conexion fallida, TLS 1.3 exclusivo o filtrado)."
    end
  else
    if h2 and hidden == "likely" then
      state = vulns.STATE.LIKELY_VULN
      out[#out + 1] = "Version oculta: verifique localmente (httpd -v)."
    elseif h2 then
      inconclusive_reason = "HTTP/2 activo pero version oculta: verifique localmente (httpd -v)."
    elseif conclusive then
      state = vulns.STATE.NOT_VULN
      out[#out + 1] = "Version oculta, pero HTTP/2 no detectado: ruta de codigo vulnerable no expuesta."
    else
      inconclusive_reason = "Version oculta y no se pudo comprobar HTTP/2 (conexion fallida, TLS 1.3 exclusivo o filtrado)."
    end
  end

  -- Resultado no concluyente: se muestra aparte, sin el encabezado "VULNERABLE:"
  if not state then
    local o = stdnse.output_table()
    o.state = "NO CONCLUYENTE"
    o.cve = "CVE-2026-119618"
    o.reason = inconclusive_reason
    o.checks = out
    return o
  end

  local vuln = {
    title = "Apache HTTP Server mod_http2 - corrupcion de memoria / RCE (severidad Critica)",
    IDS = { CVE = "CVE-2026-119618" },
    risk_factor = "High",  -- vulns solo admite High/Medium/Low; severidad real: Critica (CVSS 9.8)
    scores = { CVSSv3 = "9.8" },
    description = [[
Sincronizacion inadecuada de recursos compartidos en assign_headers() de
mod_http2 permite corrupcion de memoria y potencial ejecucion remota de codigo.
Afecta a Apache httpd 2.4.55-2.4.70 y mod_h2 (GitHub) 2.0.8-2.0.42 con h2/h2c activo.]],
    references = {
      "Boletin publicado el 11/11/2026 (verificar en https://httpd.apache.org/security/vulnerabilities_24.html)",
    },
    dates = { disclosure = { year = 2026, month = 11, day = 11 } },
    state = state,
    check_results = out,
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  return report:make_output(vuln)
end
