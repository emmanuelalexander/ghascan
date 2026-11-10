<#
.SYNOPSIS
    Instalador de ghascan para Windows.

.DESCRIPTION
    Copia la tool a %LOCALAPPDATA%\ghascan (o -Prefix), crea ghascan.cmd en
    %USERPROFILE%\.local\bin (o -Bin) y verifica Python + PyYAML.

    No descarga de ninguna URL por defecto: instala desde este checkout.
    Para instalar en otra maquina sin clonar, empaquetÃ¡ esta carpeta y
    descomprimila alli, o pasÃ¡ -Raw con la base de TU copia publicada.

.EXAMPLES
    .\install.ps1
    .\install.ps1 -Prefix D:\tools\ghascan -Bin D:\tools\bin
    .\install.ps1 -NoDeps
    .\install.ps1 -Raw https://raw.githubusercontent.com/emmanuelalexander/ghascan/main
#>
[CmdletBinding()]
param(
    [string]$Prefix = "$env:LOCALAPPDATA\ghascan",
    [string]$Bin = "$env:USERPROFILE\.local\bin",
    [string]$Raw = $env:GHASCAN_RAW,
    [switch]$NoDeps,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
function Say([string]$m) { Write-Host $m }
function Die([string]$m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Files = @('ghascan.py', 'ghascan_lib\__init__.py', 'ghascan_lib\patterns.py',
           'ghascan_lib\workflow.py', 'ghascan_lib\analyze.py', 'ghascan_lib\github.py',
           'ghascan_lib\scan.py', 'ghascan_lib\report.py')

# Python
$py = $null
foreach ($cand in @('python', 'py')) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) {
        $ver = & $cmd.Source -c "import sys; print(sys.version_info[0]*100+sys.version_info[1])" 2>$null
        if ($LASTEXITCODE -eq 0 -and [int]$ver -ge 309) { $py = $cmd.Source; break }
    }
}
if (-not $py) { Die 'Falta Python >= 3.9 en PATH.' }
Say "[1/4] Python: $py"

Say "[2/4] Instalando en $Prefix"
New-Item -ItemType Directory -Force -Path $Prefix, "$Prefix\ghascan_lib", $Bin | Out-Null

if (Test-Path "$Here\ghascan.py") {
    Say "      copiando desde $Here"
    foreach ($rel in $Files) {
        $src = Join-Path $Here $rel
        if (-not (Test-Path $src)) { Die "Falta $rel en el paquete." }
        $dst = Join-Path $Prefix $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
        Copy-Item -LiteralPath $src -Destination $dst -Force
    }
} else {
    if (-not $Raw) {
        Die ('No hay copia local de ghascan.py y no pasaste -Raw. ' +
             'Instala desde el checkout, o publica tu copia y usa -Raw <base-url>.')
    }
    Say "      descargando desde $Raw"
    foreach ($rel in $Files) {
        $url = "$Raw/" + ($rel -replace '\\', '/')
        $dst = Join-Path $Prefix $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
        try {
            Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing -ErrorAction Stop
        } catch {
            Die "No pude descargar $url"
        }
    }
}

if (-not $NoDeps) {
    Say '[3/4] Verificando PyYAML'
    & $py -c "import yaml" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Say '      instalando pyyaml'
        & $py -m pip install --user --quiet pyyaml
        if ($LASTEXITCODE -ne 0) { Say '      AVISO: sin PyYAML, se usa el fallback por regex.' }
    } else { Say '      PyYAML OK' }
} else {
    Say '[3/4] -NoDeps: no se toca pip'
}

Say "[4/4] Creando launcher $Bin\ghascan.cmd"
$cmd = @"
@echo off
"$py" "$Prefix\ghascan.py" %*
"@
Set-Content -LiteralPath (Join-Path $Bin 'ghascan.cmd') -Value $cmd -Encoding ASCII

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$Bin*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$Bin", 'User')
    Say "      PATH de usuario actualizado con $Bin (abre una terminal nueva)."
}

Say ''
& $py "$Prefix\ghascan.py" --version
Say ''
Say 'Listo. Probar en una terminal nueva:'
Say '  ghascan selftest'
Say '  ghascan demo'
Say '  ghascan scan --local .'

