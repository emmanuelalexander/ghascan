@echo off
setlocal
set "HERE=%~dp0"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 "%HERE%ghascan.py" %*
) else (
  python "%HERE%ghascan.py" %*
)
