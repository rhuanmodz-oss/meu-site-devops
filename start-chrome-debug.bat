@echo off
REM ================================================================
REM  Abre o Chrome com porta de depuracao 9222 num perfil dedicado
REM  (.chrome-debug) para o coletor conseguir anexar.
REM  IMPORTANTE: se o Chrome normal ja estiver aberto, a porta pode
REM  ser ignorada. Se nao funcionar, feche TODO o Chrome e rode de novo.
REM ================================================================
set "PROF=%~dp0.chrome-debug"

set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if not exist "%CHROME%" set "CHROME=%LocalAppData%\Google\Chrome\Application\chrome.exe"

if not exist "%CHROME%" (
  echo [ERRO] Nao encontrei o chrome.exe.
  echo Edite este .bat e ajuste a variavel CHROME para o caminho do seu Chrome.
  pause
  exit /b 1
)

REM remove lock de sessao presa, se houver
if exist "%PROF%\SingletonLock" del /q "%PROF%\SingletonLock" >nul 2>&1

echo Abrindo Chrome (porta 9222)...
echo Para conferir se a porta subiu, abra nessa janela:  http://localhost:9222/json/version
echo (se aparecer um texto JSON, esta funcionando)
echo.
start "" "%CHROME%" --remote-debugging-port=9222 --user-data-dir="%PROF%" --no-first-run --no-default-browser-check https://asn-monitor.linknetbandalarga.net/
