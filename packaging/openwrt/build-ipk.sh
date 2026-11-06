#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
	echo "Usage: $0 <binary-path> <version> <openwrt-arch> <output-ipk-path> [pkg-name]" >&2
	exit 1
fi

BIN_PATH="$1"
VERSION="$2"
ARCH="$3"
OUTPUT_IPK="$4"
PKG_NAME="${5:-murmur}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INIT_SRC="${SCRIPT_DIR}/murmur.init"
CONF_SRC="${SCRIPT_DIR}/murmur.config"

if [ ! -f "$BIN_PATH" ]; then
	echo "Error: binary not found at $BIN_PATH" >&2
	exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

DATA_DIR="${TMP_DIR}/data"
CTRL_DIR="${TMP_DIR}/control"
PKG_DIR="${TMP_DIR}/pkg"

mkdir -p \
	"${DATA_DIR}/usr/bin" \
	"${DATA_DIR}/etc/init.d" \
	"${DATA_DIR}/etc/config" \
	"${DATA_DIR}/etc/murmur" \
	"${CTRL_DIR}" \
	"${PKG_DIR}"

install -m 0755 "$BIN_PATH" "${DATA_DIR}/usr/bin/murmur"
install -m 0755 "$INIT_SRC" "${DATA_DIR}/etc/init.d/murmur"
install -m 0644 "$CONF_SRC" "${DATA_DIR}/etc/config/murmur"
chmod 0755 "${DATA_DIR}/etc/murmur"

INSTALLED_SIZE="$(
	find "$DATA_DIR" -type f -exec wc -c {} + | awk 'END { print $1 + 0 }'
)"

{
	echo "Package: ${PKG_NAME}"
	echo "Version: ${VERSION}"
	echo "Architecture: ${ARCH}"
	echo "Installed-Size: ${INSTALLED_SIZE}"
	echo "Section: net"
	echo "Priority: optional"
	echo "Maintainer: labi-le <1a6i1e@gmail.com>"
	if [ "$PKG_NAME" = "murmur-vvt" ]; then
		echo "Provides: murmur"
		echo "Conflicts: murmur"
	fi
	echo "Description: Murmur Clash-compatible proxy core for OpenWrt (procd service + --watch-config)"
} > "${CTRL_DIR}/control"

printf "/etc/config/murmur\n" > "${CTRL_DIR}/conffiles"

cat > "${CTRL_DIR}/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
for p in /etc/config/murmur /etc/init.d/murmur /etc/murmur /usr/bin/murmur; do
	grep -qxF "$p" /etc/sysupgrade.conf 2>/dev/null || echo "$p" >> /etc/sysupgrade.conf
done
exit 0
EOF
chmod 0755 "${CTRL_DIR}/postinst"

cat > "${CTRL_DIR}/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
if [ -x /etc/init.d/murmur ]; then
	/etc/init.d/murmur stop 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "${CTRL_DIR}/prerm"

printf "2.0\n" > "${PKG_DIR}/debian-binary"

tar --numeric-owner --owner=0 --group=0 -C "$CTRL_DIR" -czf "${PKG_DIR}/control.tar.gz" .
tar --numeric-owner --owner=0 --group=0 -C "$DATA_DIR" -czf "${PKG_DIR}/data.tar.gz" .

mkdir -p "$(dirname "$OUTPUT_IPK")"
OUTPUT_ABS="$(cd "$(dirname "$OUTPUT_IPK")" && pwd)/$(basename "$OUTPUT_IPK")"

tar --numeric-owner --owner=0 --group=0 -C "$PKG_DIR" -czf "$OUTPUT_ABS" \
	./debian-binary ./control.tar.gz ./data.tar.gz
