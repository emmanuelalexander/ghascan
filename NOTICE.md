# NOTICE / Procedencia

`ghascan` es una **implementación independiente**. No es un fork del proyecto
original ni contiene su código de ejecución (Redis, workers, `git_sparse`,
Docker, cola de tareas).

## Qué se derivó de `gha-vuln-scanner`

Referencia: paquete `gha-vuln-scanner` (MIT, Copyright (c) 2025 Sergio Cabrera),
tomado de la copia local `D:\Project\Tools Instaladas\test-ghs`.

| Elemento | Origen | Estado |
| --- | --- | --- |
| 43 dorks de Code Search (`QUERIES`) | `constants.py` del proyecto original | derivado, con ajustes de formato |
| Conjuntos `FULL_CONTROL`, `LIMITED_CONTROL`, `NO_CONTROL`, `PARENT_FULL_CONTROL` | idem | derivado |
| `EXPR_TRIGGERS`, `OPEN_TYPES`, `RESTRICTED_TYPES` | idem | derivado |
| Idea general de clasificar el "control del atacante" | idem | derivado |

## Qué es original de `ghascan`

- Parser de workflows (`workflow.py`) con mapeo de contexto por línea, rangos
  de jobs/steps, triggers y permisos.
- Motor de análisis (`analyze.py`): reglas R1-R8 de falsos positivos, veredicto,
  scoring y PoC benigno (`GHA_POC`).
- Clasificación de falsos positivos y trazabilidad en `eliminated`.
- Cliente de API (`github.py`) con pool multi-token, backoff y cache.
- Modos de escaneo (`scan.py`): local, repo, org, user, dork, search.
- Reportes (`report.py`): JSON, HTML autocontenido y PDF vía navegador headless.
- CLI (`ghascan.py`), instaladores, tests offline y documentación.

## Sobre la URL del upstream

Los metadatos del proyecto original declaraban
`https://github.com/nekros1xx/ghascan` como repositorio. **A la fecha
2026-11-10 ese repositorio devuelve 404**, por lo que:

- Los instaladores de este repo **no** descargan desde esa URL.
- La instalación remota requiere que publiques tu propia copia y pases
  `-Raw <base>` (PowerShell) o `GHASCAN_RAW=<base>` (sh).
- La instalación normal es local: `pipx install .`, `pip install .` o los
  scripts `install.ps1` / `install.sh` desde el checkout.

Si el upstream reaparece o cambia de URL, actualizá este archivo y el README.
