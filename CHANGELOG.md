# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/es/1.1.0/) +
[SemVer](https://semver.org/lang/es/).

## [1.0.0] - 2026-11-10

### Added

- CLI con subcomandos `demo`, `selftest`, `queries`, `scan`, `dork`, `search`.
- 43 dorks de GitHub Code Search.
- Parser de workflows con triggers, permisos, secrets, jobs, steps y contexto
  por línea.
- Motor de análisis con clasificación de control del atacante
  (`FULL_CONTROL`, `LIMITED_CONTROL`, `DISPATCH_INPUT`, `NO_CONTROL`, `UNKNOWN`).
- 8 reglas de eliminación de falsos positivos (R1-R8) con trazabilidad en
  `eliminated`.
- Veredicto con score tipo CVSS y explicación en lenguaje natural.
- PoC benigno (`GHA_POC`) que solo imprime una marca.
- Cliente de API con pool multi-token, backoff y cache.
- Modos de escaneo: local, archivo, repo, org, usuario, dork y búsqueda libre.
- Reportes JSON, HTML autocontenido y PDF vía Edge/Chrome/Chromium headless.
- Instaladores `install.ps1` (Windows) e `install.sh` (Linux/macOS), locales o
  con `-Raw`/`GHASCAN_RAW`.
- `pyproject.toml` con entry point `ghascan` para `pip`/`pipx`.
- 12 tests offline (`unittest`) + `selftest` embebido.
- Workflow `.github/workflows/tests.yml` (Ubuntu/Windows/macOS × Python 3.9/3.12/3.13).
- Documentación: `README.md`, `INSTRUCTIVO.md`, `NOTICE.md`, `LICENSE`.

### Changed

- La instalación remota ya no apunta a `nekros1xx/ghascan` (404). Requiere una
  base propia vía `-Raw` o `GHASCAN_RAW`.
- El crédito al proyecto original se movió a `NOTICE.md` con el detalle de qué
  se derivó y qué es original.
