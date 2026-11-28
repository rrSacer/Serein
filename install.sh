#!/usr/bin/env bash
set -euo pipefail

# Instalador do Serein P2P para Linux x86_64
# Funciona tanto via `curl -fsSL ... | bash` quanto executando `./install.sh` da pasta extraída.
# Instala o binário em ~/.local/share/serein-p2p/serein e cria o atalho "Serein P2P"
# sem sobrescrever nem remover o Serein original.

REPO="${SEREIN_P2P_REPO:-rrSacer/Serein}"
ASSET_NAME="serein-linux-x86_64-p2p.tar.gz"
PKG_DIR_NAME="serein-linux-x86_64-p2p"

die() { printf 'Erro: %s\n' "$*" >&2; exit 1; }
command -v install >/dev/null || die "o comando 'install' não está disponível"

ARCH="$(uname -m)"
[[ "$ARCH" == "x86_64" ]] || die "este pacote requer Linux x86_64 (detectado: $ARCH)"

TMP_DIR=""
cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

ROOT=""
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
if [[ -n "$SCRIPT_PATH" && -e "$SCRIPT_PATH" ]]; then
  ROOT="$(cd -- "$(dirname -- "$SCRIPT_PATH")" 2>/dev/null && pwd || true)"
fi

if [[ -z "$ROOT" || ! -x "$ROOT/serein" ]]; then
  command -v tar >/dev/null || die "o comando 'tar' é necessário para extrair o pacote"

  if [[ -n "${SEREIN_P2P_TAG:-}" ]]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${SEREIN_P2P_TAG}/${ASSET_NAME}"
  else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
  fi

  TMP_DIR="$(mktemp -d)"
  ARCHIVE="$TMP_DIR/$ASSET_NAME"

  printf 'Baixando Serein P2P (%s)...\n' "$DOWNLOAD_URL"
  if command -v curl >/dev/null; then
    curl -fSL --progress-bar "$DOWNLOAD_URL" -o "$ARCHIVE" \
      || die "falha ao baixar a release de $DOWNLOAD_URL"
  elif command -v wget >/dev/null; then
    wget -q --show-progress "$DOWNLOAD_URL" -O "$ARCHIVE" \
      || die "falha ao baixar a release de $DOWNLOAD_URL"
  else
    die "é necessário ter 'curl' ou 'wget' instalado para baixar o pacote"
  fi

  printf 'Extraindo pacote...\n'
  tar -xzf "$ARCHIVE" -C "$TMP_DIR"

  if [[ -x "$TMP_DIR/$PKG_DIR_NAME/serein" ]]; then
    ROOT="$TMP_DIR/$PKG_DIR_NAME"
  elif [[ -x "$TMP_DIR/serein" ]]; then
    ROOT="$TMP_DIR"
  else
    die "binário 'serein' não encontrado após extrair o pacote"
  fi
fi

BIN="$ROOT/serein"
[[ -x "$BIN" ]] || die "binário 'serein' não encontrado ou sem permissão de execução"

APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/serein-p2p"
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
APP_ENTRY_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/1024x1024/apps"

mkdir -p "$APP_DIR" "$BIN_DIR" "$APP_ENTRY_DIR" "$ICON_DIR"

# Instala o executável atomicamente (evita erro se uma instância estiver aberta)
install -m 0755 "$BIN" "$APP_DIR/serein.tmp"
mv -f "$APP_DIR/serein.tmp" "$APP_DIR/serein"

# Cria link simbólico serein-p2p sem afetar o comando serein existente
ln -sfn "$APP_DIR/serein" "$BIN_DIR/serein-p2p"

# Instala o ícone dedicado
ICON_INSTALLED=false
for icon_candidate in \
  "$ROOT/serein-p2p.png" \
  "$ROOT/serein.png" \
  "$ROOT/packaging/p2p/serein-p2p.png" \
  "$ROOT/packaging/linux/hicolor/1024x1024/apps/serein.png"; do
  if [[ -f "$icon_candidate" ]]; then
    install -m 0644 "$icon_candidate" "$ICON_DIR/serein-p2p.png"
    ICON_INSTALLED=true
    break
  fi
done

if $ICON_INSTALLED; then
  ICON_VAL="$ICON_DIR/serein-p2p.png"
else
  ICON_VAL="serein"
fi

# Cria o arquivo de atalho (.desktop) específico para a versão P2P
cat > "$APP_ENTRY_DIR/serein-p2p.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Serein P2P
Comment=Cliente Serein com transmissão de tela direta P2P (QUIC / LAN / Tailscale)
Exec=$APP_DIR/serein
Icon=$ICON_VAL
StartupWMClass=cz.viceverse.serein
Terminal=false
Categories=Network;InstantMessaging;
EOF
chmod 0644 "$APP_ENTRY_DIR/serein-p2p.desktop"

# Atualiza cache de aplicativos se a ferramenta existir
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APP_ENTRY_DIR" >/dev/null 2>&1 || true

# Verificação não-bloqueante dos plugins GStreamer necessários para captura no Linux
check_runtime_gst() {
  if ! command -v gst-inspect-1.0 >/dev/null 2>&1; then
    printf '\nAviso: gst-inspect-1.0 não encontrado; certifique-se de ter PipeWire + GStreamer base/good instalados para transmitir tela.\n'
    return 0
  fi

  local missing=()
  for plugin in pipewiresrc videorate identity capsfilter tee queue appsink; do
    if ! gst-inspect-1.0 "$plugin" >/dev/null 2>&1; then
      missing+=("$plugin")
    fi
  done

  if ! gst-inspect-1.0 videoconvertscale >/dev/null 2>&1; then
    if ! gst-inspect-1.0 videoconvert >/dev/null 2>&1 || ! gst-inspect-1.0 videoscale >/dev/null 2>&1; then
      missing+=("videoconvert/videoscale")
    fi
  fi

  if (( ${#missing[@]} > 0 )); then
    printf '\n⚠️  Plugins GStreamer essenciais ausentes para captura de tela: %s\n' "${missing[*]}"
    printf '   O modo software embutido (OpenH264) NÃO precisa de codec de hardware nem gst-plugins-bad/libav,\n'
    printf '   mas precisa da captura base do PipeWire + GStreamer:\n'
    printf '   • Ubuntu/Debian: sudo apt install gstreamer1.0-pipewire gstreamer1.0-plugins-base gstreamer1.0-plugins-good\n'
    printf '   • Fedora:        sudo dnf install pipewire-gstreamer gstreamer1-plugins-base gstreamer1-plugins-good\n'
    printf '   • Arch Linux:    sudo pacman -S gst-plugin-pipewire gst-plugins-base gst-plugins-good\n'
  fi
}

printf '\n======================================================\n'
printf '  Serein P2P instalado com sucesso!\n'
printf '======================================================\n'
printf '• Atalho criado: %s\n' "$APP_ENTRY_DIR/serein-p2p.desktop"
printf '  (O seu atalho do Serein original foi totalmente preservado)\n'
printf '• Executável instalado em: %s\n' "$APP_DIR/serein"
printf '• Comando via terminal: %s/serein-p2p\n\n' "$BIN_DIR"
printf 'Você já pode abrir o "Serein P2P" pelo menu de aplicativos!\n'
check_runtime_gst
