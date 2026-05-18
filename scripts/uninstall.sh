#!/bin/sh
set -eu

BINARY_NAME="${BINARY_NAME:-cloud-cert-bot}"
SERVICE_NAME="${SERVICE_NAME:-cloud-cert-bot}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/cloud-cert-bot}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/${SERVICE_NAME}.service}"
KEEP_CONFIG="${KEEP_CONFIG:-0}"

require_command() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required command: $1" >&2
		exit 1
	}
}

if [ "$(id -u)" -ne 0 ]; then
	echo "run this uninstaller as root, for example: curl -fsSL https://raw.githubusercontent.com/panjiang/cloud-cert-bot/main/scripts/uninstall.sh | sudo sh" >&2
	exit 1
fi

require_command rm
require_command systemctl

if systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1; then
	systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
fi

if [ -f "$SERVICE_FILE" ]; then
	rm -f "$SERVICE_FILE"
	echo "Removed systemd service: $SERVICE_FILE"
else
	echo "Systemd service not present: $SERVICE_FILE"
fi

systemctl daemon-reload
systemctl reset-failed >/dev/null 2>&1 || true

binary_path="${INSTALL_DIR}/${BINARY_NAME}"
if [ -f "$binary_path" ]; then
	rm -f "$binary_path"
	echo "Removed binary: $binary_path"
else
	echo "Binary not present: $binary_path"
fi

if [ "$KEEP_CONFIG" = "1" ]; then
	echo "Keeping config directory: $CONFIG_DIR"
elif [ -d "$CONFIG_DIR" ]; then
	rm -rf "$CONFIG_DIR"
	echo "Removed config directory: $CONFIG_DIR"
else
	echo "Config directory not present: $CONFIG_DIR"
fi

echo "Uninstall complete."
