# SDD — Escaneo de Subred (Macrosesión)

**Proyecto:** ARES
**Feature branch sugerida:** `feature/subnet-scan-macrosession`
**Estado:** Diseño cerrado, listo para scaffolding
**Ámbito de este documento:** contrato de datos, módulos, flujos y UI de esta feature al completo, incluida la vista de pantalla partida (está dentro del alcance, no es trabajo futuro). NO diseña la arquitectura interna de FastAPI (routers/services/repositories) — esa decisión está pendiente de su propia sesión de Arquitectura & Decisiones y no debe anticiparse aquí.

**Nota para quien implemente (Claude Code):** este documento describe funcionalidad que debe quedar operativa de extremo a extremo, no un esqueleto o un plan a futuro. Cada sección tiene un criterio de aceptación verificable en §9; el trabajo no se da por terminado hasta que esos criterios se cumplen de forma demostrable (contra el laboratorio Docker y/o los datos de seed de §8), no solo compilable.

---

## 1. Objetivo

Permitir que, al crear una sesión, el usuario elija entre:

1. **Target individual** (comportamiento actual, sin cambios).
2. **Subred** (nuevo): ARES descubre dispositivos en la subred mediante protocolos de auto-anuncio, los clasifica, dibuja un mapa circular (router en el centro, dispositivos alrededor) y lanza el pipeline de agente completo contra cada uno de forma **secuencial**. Al hacer click sobre un dispositivo del mapa, la pantalla se divide y la mitad inferior muestra la sesión de ese host **exactamente como si fuera un target individual** (mismos componentes de vista que ya existen para sesión única, sin duplicar UI).

La pantalla partida es parte del alcance funcional de esta feature, no una fase posterior.

## 2. Fuera de alcance (explícito)

- Descubrimiento activo por ARP o ICMP ping sweep. Solo protocolos de auto-anuncio (ver §4).
- Ejecución en paralelo de los hosts descubiertos.
- Gestión de errores avanzada del agente (timeouts de razonamiento, detección de bucles, reintentos). Un fallo se marca y punto; el hardening es trabajo de una versión futura.
- Diseño de la arquitectura de endpoints FastAPI (routers/services/repositories). Este documento define únicamente qué operaciones deben existir, no cómo se organiza el código del servidor.
- Máscara de subred mayor a una C (/24). No validar ni soportar rangos superiores.

## 3. Modelo de datos

### 3.1 Tabla `sessions` (base de datos `ares_sessions`)

Cambios sobre el esquema ya existente:

| Columna | Tipo | Notas |
|---|---|---|
| `parent_session_id` | `CHAR(36)` (o el tipo de PK ya usado para `session_id`), **NULLABLE**, `FOREIGN KEY REFERENCES sessions(id) ON DELETE CASCADE` | `NULL` = sesión individual. Con valor = subsesión hija de una macrosesión. Una fila **referenciada** por otras (aunque su propio `parent_session_id` sea `NULL`) es, por definición, una macrosesión. No se añade `session_type`: es inferible. |
| `host_status` | `ENUM('pending','running','complete','failed')` | Solo aplica a subsesiones hijas. |
| `failure_reason` | `TEXT`, `NULLABLE` | Texto libre. MVP: mensaje de excepción capturado. |
| `device_type` | `VARCHAR`, `NULLABLE` | Solo subsesiones hijas. Resultado de clasificación por *service type* (§5.3). `NULL`/`"unknown"` si no se pudo clasificar. |
| `discovery_metadata` | `JSON`, `NULLABLE` | IP, MAC si disponible, service types anunciados, puerto de respuesta. Sirve para poblar el nodo del mapa sin re-consultar Elasticsearch. |

**Cascada:** `ON DELETE CASCADE` de macrosesión hacia subsesiones hijas.

**Consulta necesaria para el sidebar (§7.1):** el backend debe poder distinguir de forma barata "sesiones individuales" (para la mitad superior del listado) de "macrosesiones" (para la mitad inferior). Dado que no hay `session_type`, esto se resuelve con dos queries (o una con `UNION`):
- Individuales: `parent_session_id IS NULL AND id NOT IN (SELECT DISTINCT parent_session_id FROM sessions WHERE parent_session_id IS NOT NULL)`.
- Macrosesiones: `id IN (SELECT DISTINCT parent_session_id FROM sessions WHERE parent_session_id IS NOT NULL)`.

Si esta doble consulta resulta cara en la práctica, es aceptable materializar un `is_macrosession BOOLEAN` calculado al crear la macrosesión (denormalización explícita, no lo mismo que el `session_type` descartado antes — aquí es una optimización de lectura, no un campo redundante con la relación misma). Decisión de implementación, no bloqueante.

### 3.2 Elasticsearch (`ares-logs`)

Sin cambios de mapping. Cada subsesión escribe sus documentos de log igual que una sesión individual.

## 4. Descubrimiento de dispositivos — proceso lineal, NO herramientas de agente

**Importante — corrección de diseño respecto a versiones previas de este documento:** `mdns_scanner` y `ssdp_scanner` **no son tools del agente**. No se registran en el `ToolRegistry`, no las invoca el LLM, no siguen la interfaz `BaseTool`. Son un **proceso lineal de backend, determinista y siempre igual**: se ejecutan en un orden fijo (mDNS, luego SSDP), sin que ningún modelo decida si ejecutarlas o cómo interpretarlas más allá del mapeo fijo de `service_type → device_type`.

### 4.1 Ubicación en el monorepo

Van en un módulo de descubrimiento propio dentro del backend, **separado de `agent/`**:

```
server/
  discovery/
    __init__.py
    mdns_scanner.py
    ssdp_scanner.py
    classifier.py        # mapeo service_type → device_type
    orchestrator.py       # fase 1 completa: ejecuta ambos scanners, agrega, deduplica, crea subsesiones
```

`orchestrator.py` es el único punto de entrada que invoca el endpoint de creación de macrosesión (§6). No expone nada al agente ni al `ToolRegistry` de `agent/`.

### 4.2 Protocolos (alcance cerrado)

- **mDNS/Bonjour**: librería `zeroconf`.
- **UPnP/SSDP**: `M-SEARCH` multicast a `239.255.255.250:1900` implementado a mano con `socket` UDP (sin librería de terceros).

Documentar en `docs/decisions/` que el descubrimiento es pasivo/semi-pasivo y de auto-anuncio: solo aparecen dispositivos que se anuncian activamente. No es un descubrimiento exhaustivo de la subred.

### 4.3 Clasificación de dispositivo

A partir del *service type* devuelto por el propio protocolo, en `classifier.py`. Ejemplos mínimos de partida:

```
_googlecast._tcp    → chromecast
_airplay._tcp       → apple_tv
_ipp._tcp           → printer
_http._tcp          → generic_web_device
urn:schemas-upnp-org:device:MediaRenderer          → media_renderer
urn:schemas-upnp-org:device:InternetGatewayDevice  → router
(sin match)         → unknown
```

La tabla de mapeo puede vivir como `dict` en `classifier.py` o como fichero JSON/YAML separado si se prevé que crecerá — decisión de implementación no bloqueante.

## 5. Orquestación

### 5.1 Fase 1 — Descubrimiento (`orchestrator.py`)

1. Usuario elige "Subred", introduce CIDR (máx. `/24`).
2. Se crea la fila `sessions` de la macrosesión.
3. `orchestrator.py` ejecuta `mdns_scanner` y después `ssdp_scanner` (secuencial entre sí).
4. Se agregan y deduplican resultados por IP.
5. Por cada host único: se clasifica, se crea subsesión hija (`host_status = 'pending'`, `device_type`, `discovery_metadata`).
6. Fin de fase 1. El mapa ya puede pintarse con todos los nodos en `pending`.

### 5.2 Fase 2 — Ejecución del agente (secuencial, host a host)

Esta fase sí usa el agente ya existente (`agent/core/agent.py`), reutilizado sin modificar su pipeline interno: por cada subsesión hija, se lanza el mismo ReAct completo (RECON→ENUMERATION→VULN_SCAN→REPORT) que ya corre hoy contra un target individual, usando el target = IP de la subsesión.

1. Iterar subsesiones hijas en orden de creación.
2. Por cada una: `host_status → 'running'`, lanzar pipeline.
3. Éxito: `host_status → 'complete'`.
4. Excepción no capturada: `host_status → 'failed'`, `failure_reason = "exception: <mensaje>"`. La macrosesión **continúa** con el siguiente host.
5. Al terminar todos: macrosesión `complete`, resumen agregable por `COUNT(...) GROUP BY host_status`.

**Nota de rendimiento:** secuencial por restricción de hardware (RTX 4070 8GB, `deepseek-r1:32b` local) — decisión de diseño aceptada, no paralelizar.

## 6. Contrato de API (agnóstico de arquitectura interna)

- `POST /sessions` — payload `{ "mode": "single", "target": "..." }` o `{ "mode": "subnet", "cidr": "192.168.1.0/24" }`. Si `mode = "subnet"`, dispara fase 1 (vía `discovery/orchestrator.py`) y devuelve `macrosession_id` + lista de subsesiones creadas con `device_type` y `host_status = 'pending'`.
- `POST /sessions/{macrosession_id}/run` — dispara fase 2 (ejecución secuencial del agente).
- `GET /sessions/{macrosession_id}` — macrosesión + estado agregado de sus hijas (para el mapa y su progreso).
- `GET /sessions?type=individual` / `GET /sessions?type=macro` — listados separados para las dos mitades del sidebar (§7.1). Alternativamente un único `GET /sessions` con el campo derivado ya resuelto en cada fila, y que el frontend filtre — decisión de implementación, cualquiera de las dos es válida.
- `GET /sessions/{child_session_id}` — sin cambios respecto al comportamiento ya existente para sesión individual. **Este mismo endpoint es el que alimenta la vista de pantalla partida** (§7.3): una subsesión hija se consulta y se renderiza exactamente igual que un target individual, sin endpoint especial.

## 7. Frontend

### 7.1 Sidebar izquierdo

El listado lateral de sesiones se divide en dos mitades fijas:

- **Mitad superior:** sesiones individuales (target único), orden cronológico como ya existe hoy.
- **Mitad inferior:** macrosesiones (escaneos de subred), cada una mostrando su CIDR y un resumen de progreso (p. ej. "6/8 completados, 1 fallido").

Click en una sesión individual → vista de sesión única ya existente, sin cambios.
Click en una macrosesión → vista de mapa de topología (§7.2).

### 7.2 Vista de mapa de topología

Layout circular: router en el centro, dispositivos descubiertos alrededor, icono según `device_type`, indicador visual de color/estado según `host_status` (`pending`/`running`/`complete`/`failed`).

Esta vista ocupa la mitad superior de la pantalla de macrosesión. La mitad inferior empieza vacía (placeholder tipo "selecciona un dispositivo del mapa") y se puebla al hacer click en un nodo (§7.3).

### 7.3 Pantalla partida (dentro de alcance)

Al hacer click en un nodo del mapa:

1. La mitad inferior de la pantalla se activa y renderiza los mismos componentes ya usados para ver una sesión individual (informe, grafo de eventos/replay, etc.), pero **embebidos en el panel inferior**, no navegando a una ruta nueva de página completa.
2. Esos componentes deben aceptar el `session_id` de la subsesión como prop/parámetro en vez de asumir que viene de la ruta de React Router — es el único ajuste estructural necesario sobre los componentes de vista de sesión individual ya existentes, para poder reutilizarlos embebidos.
3. El mapa (mitad superior) permanece visible y interactivo: click en otro nodo reemplaza el contenido de la mitad inferior por la sesión de ese otro host, sin recargar la vista completa.

**Nota de arquitectura de estado:** dado que ya identificasteis que React Router desmonta componentes al navegar entre tabs (de ahí que el estado del grafo deba vivir en `AppLayout` vía `AppOutletContext`), aquí aplica el mismo cuidado: el `session_id` seleccionado en el mapa debe vivir en el estado del componente contenedor de la vista de macrosesión (no en la URL, salvo que se decida reflejarlo también ahí como parámetro opcional para poder compartir el enlace directo a un host concreto — decisión de implementación, no bloqueante).

### 7.4 Mocks primero

Igual que el resto del frontend del proyecto: `types/` → `SubnetScanNode`, `SubnetScanTopology` → mock con 5-8 nodos variados en `device_type` y `host_status` → construir mapa y pantalla partida contra el mock → conectar a `GET /sessions/{macrosession_id}` real al final.

## 8. Datos de prueba (seed)

Igual que en la versión anterior de este documento — sin cambios sobre esta sección:

- Script `scripts/seed_demo_subnet_scan.py`, idempotente, opera sobre usuarios ya existentes en `ares_config` (no crea usuarios nuevos).
- Por usuario: una macrosesión de ejemplo (CIDR falso plausible) + 5-8 subsesiones hijas con `device_type` variado (`chromecast`, `printer`, `router`, `unknown`) y `host_status` variado (al menos una `complete`, una `failed` con `failure_reason` de ejemplo, opcionalmente `pending`/`running`).
- Para las `complete`, generar también 2-3 eventos falsos en `ares_sessions.events` para que la pantalla partida no aparezca vacía al probarla.
- Salvaguarda: rechazar ejecución si `ENV == "production"`. Datos inequívocamente falsos (rangos privados estándar).

## 9. Criterios de aceptación (funcionalidad real, no solo scaffolding)

- [ ] Migración de `sessions` aplicada sin romper sesiones individuales existentes.
- [ ] Crear una macrosesión sobre una subred `/24` de laboratorio (Docker) produce subsesiones hijas correctamente clasificadas por `device_type`, usando `server/discovery/` — sin que ninguna de estas herramientas aparezca registrada en el `ToolRegistry` del agente.
- [ ] Lanzar fase 2 ejecuta el pipeline ReAct real (no un stub) contra cada subsesión, en orden, y persiste `host_status` correctamente en cada transición.
- [ ] Un fallo forzado en un host intermedio (p. ej. IP inalcanzable) se marca `failed` con `failure_reason` poblado, y el siguiente host se procesa igualmente.
- [ ] El sidebar muestra correctamente sesiones individuales arriba y macrosesiones abajo, con datos reales (no solo maquetado).
- [ ] Click en un nodo del mapa puebla la mitad inferior de la pantalla con la vista de sesión real de esa subsesión (informe/grafo), sin navegar a una página distinta, y permite cambiar de host sin perder el mapa.
- [ ] El script de seed puebla datos de demo para usuarios existentes, es idempotente, y no interfiere con la suite de pytest.
- [ ] Queda una entrada en `docs/decisions/` documentando la limitación de cobertura del descubrimiento (solo dispositivos de auto-anuncio).

---

*Documento de diseño cerrado en sesión de Arquitectura & Decisiones. Arquitectura interna de FastAPI explícitamente fuera de alcance — pendiente de sesión propia antes de iniciar trabajo en `server/`. Todo lo demás descrito aquí es funcionalidad a entregar operativa, no un plan.*
