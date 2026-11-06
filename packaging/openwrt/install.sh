#!/bin/sh
set -eu

MURMUR_TAG="${MURMUR_TAG:-Prerelease-Alpha}"
MURMUR_REPO="${MURMUR_REPO:-labi-le/murmur}"

arch="$(uname -m)"
case "$arch" in
	aarch64)
		variant="${MURMUR_VARIANT:-vvt}"
		case "$variant" in
			vvt)
				ipk_arch="aarch64_generic"
				pkg_prefix="murmur-vvt"
				bin_prefix="murmur-linux-arm64-vvt"
				;;
			full)
				ipk_arch="aarch64_generic"
				pkg_prefix="murmur"
				bin_prefix="murmur-linux-arm64"
				;;
			*)
				echo "Error: unsupported MURMUR_VARIANT='$variant' (expected 'vvt' or 'full')" >&2
				exit 1
				;;
		esac
		;;
	x86_64)
		ipk_arch="x86_64"
		pkg_prefix="murmur"
		bin_prefix="murmur-linux-amd64"
		;;
	mipsel*)
		ipk_arch="mipsel_24kc"
		pkg_prefix="murmur"
		bin_prefix="murmur-linux-mipsle-softfloat"
		;;
	*)
		echo "Error: unsupported architecture '$arch'" >&2
		exit 1
		;;
esac

fetch() {
	url="$1"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- "$url"
	else
		echo "Error: neither curl nor wget is available" >&2
		exit 1
	fi
}

base_release_url="https://github.com/${MURMUR_REPO}/releases/download/${MURMUR_TAG}"
base_raw_url="https://raw.githubusercontent.com/${MURMUR_REPO}/main/packaging/openwrt"

version="$(fetch "${base_release_url}/version.txt" | tr -d '[:space:]')"
if [ -z "$version" ]; then
	echo "Error: failed to determine version from ${base_release_url}/version.txt" >&2
	exit 1
fi

if command -v opkg >/dev/null 2>&1; then
	ipk_url="${base_release_url}/${pkg_prefix}_${version}_${ipk_arch}.ipk"
	fetch "$ipk_url" > /tmp/murmur.ipk
	opkg install /tmp/murmur.ipk
	rm -f /tmp/murmur.ipk
else
	bin_url="${base_release_url}/${bin_prefix}-${version}.gz"
	mkdir -p /usr/bin /etc/init.d /etc/config /etc/murmur
	fetch "$bin_url" | gunzip -c > /usr/bin/murmur.new
	chmod 0755 /usr/bin/murmur.new
	mv -f /usr/bin/murmur.new /usr/bin/murmur

	fetch "${base_raw_url}/murmur.init" > /etc/init.d/murmur.new
	chmod 0755 /etc/init.d/murmur.new
	mv -f /etc/init.d/murmur.new /etc/init.d/murmur

	if [ ! -f /etc/config/murmur ]; then
		fetch "${base_raw_url}/murmur.config" > /etc/config/murmur
		chmod 0644 /etc/config/murmur
	fi

	for p in /etc/config/murmur /etc/init.d/murmur /etc/murmur /usr/bin/murmur; do
		grep -qxF "$p" /etc/sysupgrade.conf 2>/dev/null || echo "$p" >> /etc/sysupgrade.conf
	done
fi

/usr/bin/murmur -v
