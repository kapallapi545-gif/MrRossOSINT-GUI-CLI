@echo off
rem Uruchamia interfejs graficzny MrRossOSINT-GUI bez okna konsoli.
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%~dp0osint_gui.py"
) else (
    start "" python "%~dp0osint_gui.py"
)
