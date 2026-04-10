#!/usr/bin/env bash
# ============================================================
#  EXE Decompiler Tool - Instalador Linux / macOS
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║     EXE Decompiler Tool - Installer      ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ---- Check Python 3 ----
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERRO] Python 3 não encontrado. Instala com:${NC}"
    echo "  Ubuntu/Debian : sudo apt install python3 python3-pip python3-venv"
    echo "  macOS         : brew install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1)
echo -e "${GREEN}[OK] ${PYTHON_VERSION}${NC}"

# ---- Create virtual environment ----
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[*] A criar ambiente virtual...${NC}"
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
echo -e "${GREEN}[OK] Ambiente virtual ativado${NC}"

# ---- Install Python dependencies ----
echo -e "${YELLOW}[*] A instalar dependências Python...${NC}"
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo -e "${GREEN}[OK] Dependências Python instaladas${NC}"

# ---- Check optional tools ----
echo ""
echo -e "${CYAN}[*] A verificar ferramentas opcionais...${NC}"

if command -v upx &>/dev/null; then
    echo -e "${GREEN}  [OK] UPX encontrado: $(upx --version 2>&1 | head -1)${NC}"
else
    echo -e "${YELLOW}  [!] UPX não encontrado (opcional - necessário para unpack de EXEs comprimidos)${NC}"
    echo "      Instala com: sudo apt install upx  |  brew install upx"
fi

if command -v ilspycmd &>/dev/null; then
    echo -e "${GREEN}  [OK] ILSpy CLI encontrado${NC}"
else
    echo -e "${YELLOW}  [!] ilspycmd não encontrado (opcional - necessário para .NET decompilation)${NC}"
    echo "      Instala com: dotnet tool install -g ilspycmd"
fi

# ---- Done ----
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗"
echo "║       Instalação concluída com sucesso!   ║"
echo "╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "Uso: ${CYAN}source .venv/bin/activate${NC}"
echo -e "     ${CYAN}python decompiler.py <ficheiro.exe>${NC}"
echo ""
