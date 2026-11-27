#!/usr/bin/env bash
set -euo pipefail

# Instalador do Serein P2P para Linux x86_64
# Instala o binário em ~/.local/share/serein-p2p/serein
# Cria o atalho "Serein P2P" sem sobrescrever nem remover o Serein original.

die() { printf 'Erro: %s\n' "$*" >&2; exit 1; }
command -v install >/dev/null || die "o comando install não está disponível"

ARCH="$(uname -m)"
[[ "$ARCH" == "x86_64" ]] || die "este pacote requer Linux x86_64 (detectado: $ARCH)"

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN="$ROOT/serein"
[[ -x "$BIN" ]] || die "binário 'serein' não encontrado na pasta extraída; execute o script a partir da pasta extraída"

APP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/serein-p2p"
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
APP_ENTRY_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICON_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/1024x1024/apps"

mkdir -p "$APP_DIR" "$BIN_DIR" "$APP_ENTRY_DIR" "$ICON_DIR"

# Instala o executável atomicamente
install -m 0755 "$BIN" "$APP_DIR/serein.tmp"
mv -f "$APP_DIR/serein.tmp" "$APP_DIR/serein"

# Cria link simbólico serein-p2p sem afetar o comando serein existente
ln -sfn "$APP_DIR/serein" "$BIN_DIR/serein-p2p"

# Instala o ícone dedicado
ICON_INSTALLED=false
for icon_candidate in "$ROOT/serein-p2p.png" "$ROOT/serein.png" "$ROOT/packaging/p2p/serein-p2p.png" "$ROOT/packaging/linux/hicolor/1024x1024/apps/serein.png"; do
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

printf '\n======================================================\n'
printf '  Serein P2P instalado com sucesso!\n'
printf '======================================================\n'
printf '• Atalho criado: %s\n' "$APP_ENTRY_DIR/serein-p2p.desktop"
printf '  (O seu atalho do Serein original foi totalmente preservado)\n'
printf '• Executável instalado em: %s\n' "$APP_DIR/serein"
printf '• Comando via terminal: serein-p2p (em %s)\n\n' "$BIN_DIR"
printf 'Você já pode abrir o "Serein P2P" pelo menu de aplicativos!\n'
