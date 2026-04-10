@echo off
REM ============================================================
REM  EXE Decompiler Tool - Instalador Windows
REM ============================================================

echo.
echo ========================================
echo   EXE Decompiler Tool - Installer
echo ========================================
echo.

REM ---- Check Python ----
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERRO] Python nao encontrado.
    echo Instala a partir de https://www.python.org/downloads/
    echo Certifica-te de que "Add Python to PATH" esta ativado.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [OK] %PYVER%

REM ---- Create virtual environment ----
if not exist ".venv" (
    echo [*] A criar ambiente virtual...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
echo [OK] Ambiente virtual ativado

REM ---- Install dependencies ----
echo [*] A instalar dependencias Python...
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo [OK] Dependencias instaladas

REM ---- Check optional tools ----
echo.
echo [*] A verificar ferramentas opcionais...

where upx >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo   [OK] UPX encontrado
) else (
    echo   [!] UPX nao encontrado ^(opcional - necessario para unpack de EXEs comprimidos^)
    echo       Transfere de https://github.com/upx/upx/releases
)

where ilspycmd >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo   [OK] ILSpy CLI encontrado
) else (
    echo   [!] ilspycmd nao encontrado ^(opcional - necessario para .NET decompilation^)
    echo       Instala com: dotnet tool install -g ilspycmd
)

REM ---- Done ----
echo.
echo ========================================
echo   Instalacao concluida com sucesso!
echo ========================================
echo.
echo Uso: .venv\Scripts\activate.bat
echo      python decompiler.py ^<ficheiro.exe^>
echo.
pause
