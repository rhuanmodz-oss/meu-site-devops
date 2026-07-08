@echo off
REM ================================================================
REM  FlowSpec SOC - coletor automatico
REM  Roda o collector.py na pasta deste .bat, em loop, publicando
REM  no GitHub a cada ciclo. Fecha? E so abrir de novo.
REM ================================================================
cd /d "%~dp0"
title FlowSpec SOC Collector

:loop
echo [%date% %time%] iniciando coletor...
python collector.py --interval 30 --grafana-wait 12000
echo.
echo [%date% %time%] coletor parou. Reiniciando em 10s (Ctrl+C para sair)...
timeout /t 10 /nobreak >nul
goto loop
