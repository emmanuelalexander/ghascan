# ghascan

[![tests](https://github.com/emmanuelalexander/ghascan/actions/workflows/tests.yml/badge.svg)](https://github.com/emmanuelalexander/ghascan/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![version](https://img.shields.io/badge/version-1.0.0-informational.svg)](CHANGELOG.md)

**GitHub Actions expression-injection dorker + SAST.**

Encuentra workflows que interpolan datos controlados por el atacante
(`issue.title`, `pull_request.body`, `comment.body`, `head_ref`, labels,
`toJSON(...)`, `format(...)`, `inputs.*`) dentro de bloques `run:` o `script:`.
Eso permite inyeccion de comandos y, en un runner con secrets, RCE en el canal CI.

- **43 dorks** de GitHub Code Search, uno por vector real.
- **Multi-token**: rota claves y respeta el rate limit de code search.
- **Escanea organizaciones enteras** (o un repo, un usuario, una carpeta local).
- **Elimina falsos positivos** con 8 reglas (comentarios, jobs/steps desactivados,
  trigger incorrecto, `env:`/`with:`, gates de match exacto, heredocs citados).
- **Reportes JSON + HTML + PDF** con PoC benigno listo para triage.
- **Sin dependencias pesadas**: Python 3.9+ y PyYAML (opcional).
- **Instalacion de una linea** en Linux/macOS y Windows.

```
$ ghascan scan --local .
CRITICAL  .github/workflows/pr-title.yml  ${{ github.event.pull_request.title }}
FALSE_POSITIVE  .github/workflows/safe.yml
...
```

---

## Instalacion

Hay dos caminos reales: `pip`/`pipx` (recomendado) o los scripts del checkout.

### pip / pipx (recomendado)

```sh
git clone https://github.com/emmanuelalexander/ghascan.git
cd ghascan
pipx install .          # aislado, deja el comando `ghascan`
# o: python -m pip install --user .
```

Verificar:

```sh
ghascan --version
ghascan selftest
```

### Windows (PowerShell)

Desde el checkout:

```powershell
cd "D:\Project\Tools Instaladas\ghascan"
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

El instalador copia la tool a `%LOCALAPPDATA%\ghascan`, crea `ghascan.cmd` en
`%USERPROFILE%\.local\bin` y agrega esa carpeta al PATH del usuario.

### Linux / macOS

Desde el checkout:

```sh
chmod +x install.sh && ./install.sh
```

Deja la tool en `~/.local/share/ghascan` y el launcher en `~/.local/bin/ghascan`.

### Instalacion remota (one-liner)

Los instaladores **no** descargan de ninguna URL por defecto. Para usar la copia
publicada en este repo, pasá la base `raw`:

```sh
curl -fsSL https://raw.githubusercontent.com/emmanuelalexander/ghascan/main/install.sh \
  | GHASCAN_RAW=https://raw.githubusercontent.com/emmanuelalexander/ghascan/main sh
```

```powershell
iwr -useb https://raw.githubusercontent.com/emmanuelalexander/ghascan/main/install.ps1 -OutFile "$env:TEMP\ghascan-install.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\ghascan-install.ps1" -Raw https://raw.githubusercontent.com/emmanuelalexander/ghascan/main
```

El segundo comando evita el error de política de ejecución de scripts. Si ya
tenés el repo clonado, alcanza con `.\install.ps1`.

Si publicás un fork, reemplazá `emmanuelalexander` por tu org.

### Instalacion local desde el checkout

Los scripts también funcionan sin red si ya tenés el repo clonado. Ver las
secciones de Windows y Linux/macOS arriba.

> El proyecto original declaraba `github.com/nekros1xx/ghascan` en sus
> metadatos, pero ese repositorio hoy devuelve **404**. Por eso el one-liner de
> arriba apunta a esta copia publicada y no a esa URL rota. Ver `NOTICE.md`.

### Sin instalar

```sh
python ghascan.py demo
python ghascan.py scan --local .
```

Requisito: Python >= 3.9. `pip install pyyaml` es opcional (sin PyYAML el
parser usa un fallback por regex y pierde algo de precision en `permissions`).

---

## Primeros pasos (sin token)

```sh
ghascan selftest     # 12 pruebas internas del analizador
ghascan demo         # escanea 8 workflows de ejemplo y genera reportes
ghascan queries      # lista los 43 dorks
ghascan scan --local /ruta/al/repo
```

`demo` y `selftest` no tocan la red ni necesitan credenciales.

---

## Token de GitHub

`dork` y `search` usan la API de Code Search, que **requiere autenticacion**.
`scan --repo/--org/--user` funciona sin token (60 req/h), pero con token es mas
rapido y permite repos privados.

```sh
export GITHUB_TOKEN=ghp_xxx                 # un token
export GITHUB_TOKENS=ghp_a,ghp_b,ghp_c      # varios (round-robin)
ghascan dork --queries 1,2,3 --max 50
```

o:

```sh
ghascan dork --all --token ghp_a --token ghp_b --max 100
ghascan dork --all --tokens-file tokens.txt
```

Permisos minimos: lectura de codigo y metadata. Para repos privados, el token
necesita acceso a esos repos.

Cada token puede hacer ~10 busquedas de codigo por minuto. Con 3 tokens el
dorking completo de 43 queries tarda ~2-3 minutos en vez de ~5.

---

## Modos

| Comando | Que hace | Token |
| --- | --- | --- |
| `ghascan demo` | workflows de ejemplo, sin red | no |
| `ghascan selftest` | pruebas del analizador | no |
| `ghascan queries` | lista los 43 dorks | no |
| `ghascan scan --local DIR` | escanea `.github/workflows/*.yml` | no |
| `ghascan scan --file WF.yml` | un workflow suelto | no |
| `ghascan scan --repo OWNER/NAME` | un repositorio | opcional |
| `ghascan scan --org ORG` | todos los repos de una org | opcional |
| `ghascan scan --user USER` | repos de un usuario | opcional |
| `ghascan dork --queries 1-10` | code search dirigido | si |
| `ghascan dork --all --org ORG` | los 43 dorks dentro de una org | si |
| `ghascan search --query "..."` | busqueda libre + analisis | si |

### Ejemplos

```sh
# Un repo publico, sin token
ghascan scan --repo actions/checkout

# Una org entera, solo CRITICAL/HIGH, y falla el CI si aparece algo
ghascan scan --org mi-org --max-repos 200 --min-severity HIGH --fail-on CRITICAL,HIGH

# Dorking global de los vectores mas criticos
ghascan dork --queries 1,2,3,4,5,6 --max 100

# Los 43 dorks limitados a una org
ghascan dork --all --org mi-org --max 50 --format json,html,pdf

# Busqueda libre
ghascan search --query '"pull_request_target" "github.event.pull_request.title" path:.github/workflows' --max 50
```

---

## Salida

Por defecto escribe los tres formatos en `./ghascan-out/ghascan-<timestamp>.*`:

- **JSON**: datos completos, ideal para `jq`, dashboards o adjuntar a un ticket.
- **HTML**: autocontenido, con filtros por severidad y PoC desplegable.
- **PDF**: generado con Edge/Chrome/Chromium headless (si no hay navegador,
  queda el HTML y se avisa).

```sh
ghascan demo --format json --out ./out
ghascan demo --format html,pdf --out ./out
```

### Severidades

| Veredicto | Cuando |
| --- | --- |
| `CRITICAL` | dato de control total + trigger abierto + secrets o `GITHUB_TOKEN` con write |
| `HIGH` | control total con trigger abierto, o limitado con secrets/escritura |
| `MEDIUM` | trigger restringido, `workflow_dispatch`, o reusable workflow |
| `LOW` | requiere permisos altos y sin secrets |
| `FALSE_POSITIVE` | todas las expresiones fueron eliminadas por reglas |

### Reglas de eliminacion de falsos positivos

| Regla | Elimina |
| --- | --- |
| `R1_COMMENT` | linea comentada |
| `R2_JOB_DISABLED` | job con `if: false` |
| `R3_STEP_DISABLED` | step con `if: false` |
| `R4_TRIGGER` | la expresion necesita un evento que el workflow no tiene |
| `R7_ENV/WITH` | expresion en `env:` o `with:`, no interpolada como shell |
| `R7B_EXACT_GATE` | gate `if: ... == 'literal'` sobre el mismo campo |
| `R8_HEREDOC` | dentro de heredoc citado (`<<'EOF'`), sin expansion |

---

## Como funciona

1. **Descubrimiento**: code search (43 dorks), lista de repos de una org/usuario
   o archivos locales.
2. **Enriquecimiento**: lee el YAML, detecta triggers, permisos y secrets.
3. **Analisis**: busca `${{ ... }}` en contexto `run:`/`script:`, clasifica el
   control del atacante (`FULL_CONTROL`, `LIMITED_CONTROL`, `DISPATCH_INPUT`,
   `NO_CONTROL`), aplica reglas de FP y calcula el veredicto.
4. **Reporte**: genera JSON/HTML/PDF con PoC benigno y remediacion.

Los PoC solo imprimen `GHA_POC`. No exfiltran datos ni ejecutan comandos
destructivos. La idea es demostrar la ejecucion, no aprovecharla.

---

## Uso en CI

```yaml
name: gha-audit
on:
  schedule: [{ cron: '0 6 * * 1' }]
  workflow_dispatch:
jobs:
  ghascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install pyyaml
      - run: python ghascan.py scan --local . --format json,html --fail-on CRITICAL,HIGH
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ghascan-report
          path: ghascan-out/
```

`--fail-on CRITICAL,HIGH` devuelve exit code 2, lo que rompe el job a proposito.

---

## Estructura

```
ghascan/
  ghascan.py            CLI
  ghascan_lib/
    patterns.py         43 dorks + expresiones + sets de control
    workflow.py         parser YAML, triggers, jobs, steps, contextos
    analyze.py          motor de analisis, reglas FP, veredicto, PoC
    github.py           API client multi-token
    scan.py             modos local/repo/org/dork/search
    report.py           JSON/HTML/PDF
  install.sh            instalador Linux/macOS (local o -Raw)
  install.ps1           instalador Windows (local o -Raw)
  pyproject.toml        paquete instalable (pipx/pip) + entry point
  tests/                tests offline
  README.md             resumen y opciones
  INSTRUCTIVO.md        guia completa paso a paso
  NOTICE.md             procedencia y atribucion
  CHANGELOG.md          historial de versiones
  LICENSE               MIT
```

---

## Limitaciones

- No ejecuta los workflows: el veredicto es estatico y puede requerir revision
  manual en casos raros (expresiones construidas dinamicamente, reusable
  workflows con caller desconocido).
- Code search indexa el branch por defecto y tiene limite de 1000 resultados
  por query; para orgs grandes conviene `--org`.
- Sin token, `scan --repo` esta limitado a 60 req/h.
- PDF requiere Chrome/Edge/Chromium. Si no hay, usa el HTML.

---

## Creditos y procedencia

`ghascan` es una **implementacion independiente**, escrita desde cero. No
incluye el runtime del proyecto original (Redis, workers, `git_sparse`, Docker
ni cola de tareas).

Se derivaron del proyecto `gha-vuln-scanner` (MIT, Copyright (c) 2025
Sergio Cabrera), tomado de la copia local `Tools Instaladas\test-ghs`:

- los 43 dorks de Code Search,
- los conjuntos de control (`FULL_CONTROL`, `LIMITED_CONTROL`, `NO_CONTROL`),
- las tablas de triggers y su apertura.

Todo lo demas (parser, reglas R1-R8, veredicto, PoC benigno, reportes, CLI,
pool multi-token, instaladores y tests) es original de este repo.

El upstream declarado en esos metadatos (`github.com/nekros1xx/ghascan`) hoy
devuelve 404. Detalle completo en `NOTICE.md`.

## Licencia

MIT. Ver `LICENSE` (incluye ambas atribuciones).
