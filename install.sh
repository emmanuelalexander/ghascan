#!/usr/bin/env sh
# ghascan installer - Linux / macOS
#
# Uso (desde el checkout):
#   ./install.sh
#
# Instalacion remota (solo si publicaste tu propia copia):
#   GHASCAN_RAW=https://raw.githubusercontent.com/TU-ORG/ghascan/main ./install.sh
#
# Variables:
#   GHASCAN_HOME  destino de la tool        (default: ~/.local/share/ghascan)
#   GHASCAN_BIN   destino del launcher      (default: ~/.local/bin)
#   GHASCAN_RAW   base URL para descargar   (default: vacio = solo local)
set -eu

RAW="${GHASCAN_RAW:-}"
PREFIX="${GHASCAN_HOME:-$HOME/.local/share/ghascan}"
BIN="${GHASCAN_BIN:-$HOME/.local/bin}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "Falta python3 (>= 3.9)."
PY="$(command -v python3)"
"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,9) else 1)' \
  || die "Python >= 3.9 requerido (encontrado: $("$PY" -V 2>&1))."

say "[1/4] Instalando en $PREFIX"
mkdir -p "$PREFIX/ghascan_lib" "$BIN"

if [ -n "$HERE" ] && [ -f "$HERE/ghascan.py" ]; then
  say "      copiando desde $HERE"
  cp "$HERE/ghascan.py" "$PREFIX/ghascan.py"
  for f in "$HERE"/ghascan_lib/*.py; do
    [ -f "$f" ] && cp "$f" "$PREFIX/ghascan_lib/"
  done
else
  [ -n "$RAW" ] || die "No hay copia local y GHASCAN_RAW esta vacio. Instala desde el checkout o publica tu copia y exporta GHASCAN_RAW=<base-url>."
  say "      descargando desde $RAW"
  if command -v curl >/dev/null 2>&1; then
    DL="curl -fsSL"
  elif command -v wget >/dev/null 2>&1; then
    DL="wget -qO-"
  else
    die "Necesito curl o wget para la instalacion remota."
  fi
  mkdir -p "$PREFIX/ghascan_lib"
  $DL "$RAW/ghascan.py" > "$PREFIX/ghascan.py" || die "No pude descargar ghascan.py"
  for m in __init__ patterns workflow analyze github scan report; do
    $DL "$RAW/ghascan_lib/$m.py" > "$PREFIX/ghascan_lib/$m.py" \
      || die "No pude descargar ghascan_lib/$m.py"
  done
fi

say "[2/4] Verificando PyYAML"
if "$PY" -c 'import yaml' >/dev/null 2>&1; then
  say "      PyYAML OK"
else
  say "      instalando PyYAML (--user)"
  "$PY" -m pip install --user --quiet pyyaml >/dev/null 2>&1 \
    || say "      AVISO: sin PyYAML. El parser usa el fallback por regex."
fi

say "[3/4] Creando launcher $BIN/ghascan"
cat > "$BIN/ghascan" <<EOF
#!/usr/bin/env sh
exec "$PY" "$PREFIX/ghascan.py" "\$@"
EOF
chmod +x "$BIN/ghascan" "$PREFIX/ghascan.py" 2>/dev/null || true

say "[4/4] Comprobando"
"$BIN/ghascan" --version

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) say ""; say "Agrega esto a tu shell rc:"; say "  export PATH=\"$BIN:\$PATH\"" ;;
esac

say ""
say "Listo. Probar:"
say "  ghascan selftest"
say "  ghascan demo"
say "  ghascan scan --local ."
