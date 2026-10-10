@echo off
rem MrRossOSINT-GUI – wiersz poleceń. Bez argumentów otwiera menu interaktywne.
rem Przykład: osint domain example.com -o raport.html
python "%~dp0osint.py" %*
if "%~1"=="" pause
