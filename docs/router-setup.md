# Configure murmur on a router: an LLM runbook

Copy this prompt into your assistant, followed by this document or its public link:

> Help me install and configure murmur on my router using this guide. Inspect the
> device and existing network before changing anything. Ask only for information
> you cannot obtain safely, including my intended traffic scope and consent for
> network changes. Identify the exact hardware, firmware, architecture and ABI;
> do not guess from a product name. Keep SSH and the existing Internet connection
> working. Start with a separate, loopback-only proxy, verify real traffic, then
> propose any LAN/DNS/firewall changes with backups and a tested timed rollback.
> Do not expose secrets, invent downloads or unsupported features, or call a
> config-test successful connectivity. Stop at a specific prerequisite if my
> device, artifact or protocol is unsupported. Finish with reproducible checks,
> startup and rollback instructions, and clearly state what was not tested.

This document is self-contained; the recipient does not need repository access.
It is not a one-command installer. Commands below are templates for a Linux shell,
not the Keenetic management CLI. Replace uppercase placeholders locally before
execution. Never run an entire section blindly.

Fast path: **inspect -> verify artifact -> back up/arm rollback -> isolated DIRECT
test -> load subscription/select node -> verify upstream traffic -> install the
matching service -> reboot/retest**. LAN gateway changes are a separate approval
gate, not part of the initial install.

## 1. Establish scope and inspect without changes

First distinguish these outcomes:

- **Manual proxy:** applications explicitly use HTTP/SOCKS. This does not route
  all LAN traffic, DNS, UDP or devices that ignore proxy settings.
- **LAN gateway:** selected clients or the whole LAN are transparently routed.
  This additionally needs a verified firewall/routing design, DNS handling, kernel
  support, IPv6 policy and explicit owner approval. Installing a binary is not
  this integration.

Record the exact model code, hardware revision, CPU ISA, 32/64-bit userspace,
endianness, ABI/libc and dynamic loader, kernel, firmware version, init system,
firewall backend/owner, LAN/WAN interfaces, DNS owners, free RAM/storage, mounted
persistent storage and current proxy services. Record the desired protocols and
whether UDP and IPv6 must work. Do not collect passwords to answer these questions.

**Keenetic Ultra KN-1810 with Entware/SSH is not proof of ARM64 compatibility.**
Confirm the model code and actual ELF architecture; product names such as Giga,
Ultra and Titan are not architectures and can vary across revisions/regions.
KeeneticOS plus Entware is not OpenWrt. Do not apply UCI, procd, fw4, OpenWrt kernel
packages or OpenWrt boot commands to KeeneticOS. A device actually flashed with
OpenWrt follows its observed firmware, not its original branding.

Run available read-only probes individually; missing commands mean missing
information, not permission to install packages or change firmware:

```sh
uname -a
cat /proc/cpuinfo
cat /proc/meminfo
cat /proc/mounts
df -h
id
ps
cat /proc/1/comm
cat /etc/os-release
cat /etc/openwrt_release
cat /opt/etc/entware-release
for t in opkg apk ubus uci fw4 nft iptables ip ss netstat file readelf \
         sha256sum tar gzip curl wget scp sftp start-stop-daemon nohup setsid \
         openssl hexdump od pidof crond; do
    printf '%s: ' "$t"; command -v "$t" || echo MISSING
done
opkg print-architecture
file -L /bin/sh /opt/bin/opkg
readelf -h -l -A /bin/busybox
ip address show
ip route show table all
ip rule show
ip -6 route show table all
ip -6 rule show
ss -lntup
# If ss is absent, use the available netstat implementation:
netstat -lntup
cat /etc/resolv.conf
cat /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv6/conf/all/forwarding
cat /proc/modules
ls -l /dev/net/tun
```

One name per `command -v`. POSIX and BusyBox accept a single name and ignore the
rest, so `command -v opkg apk ubus ...` reports only the first result and makes
every later tool look absent. `MISSING` means "not on this `PATH`", not "not
installed": Entware places many tools under `/opt/bin` and `/opt/sbin`, so probe
from the shell the service will run in, or with the absolute path you intend to
use. `file`, `readelf`, `ldd` and the `-A`/`-t` forms of `od` are GNU or
desktop-BusyBox tools; run those probes only when the loop found them.

Use `ubus call system board` only on verified OpenWrt. On KeeneticOS, obtain the
firmware/model from its management UI or documented read-only management command,
and inspect `/opt/etc/init.d/rc.unslung`, `/opt/etc/init.d/rc.func` and the configured
OPKG startup path. Verify that SSH reaches the Entware shell, not the management
CLI; its port may differ. Do not change SSH settings during proxy setup.

Read `nft list ruleset`, `iptables-save` and `ip6tables-save` only for installed
backends, and identify who regenerates those rules. Inspect existing service
files and resolver settings locally. These outputs can contain private addresses,
VPN keys or subscription details: return a redacted inventory, not raw config.
If ELF tools are absent, copy a known system ELF to a trusted workstation for
inspection. An `od: invalid option -- 'A'` failure is missing information, not
data: plain BusyBox `od` has no `-A` or `-t`, and §2 gives the byte-level
fallback. `uname -m` alone does not establish userspace ABI, libc, MIPS
endianness or floating-point ABI. Do not run `ldd` on an untrusted binary.

## 2. Artifact and feature gate

Ask the distributor for an artifact, version/source revision, target triple,
feature profile, minimum kernel/CPU requirements and SHA-256 delivered through a
trusted channel. A checksum proves matching bytes, not who built them. Do not
substitute a similarly named third-party binary. Private GitHub releases can
return 404 to unauthenticated recipients; request a public sanitized artifact or
an authorized file transfer. Never put an access token in this document, a URL,
a shell history, a gist or an assistant transcript.

| Profile | Intended capabilities | Important exclusions |
| --- | --- | --- |
| Full/default | Every implemented proxy protocol (`extra-protocols` on), DNS, rules/providers, controller, transparent-inbound infrastructure, optional overlay engines | Availability still depends on target and runtime support |
| `router` | The same protocol set as full/default, because the profile enables `extra-protocols`; WireGuard, DNS/rules/controller, TUN/redir/TPROXY infrastructure; lower-memory build | EasyTier/Wasmtime/WASI, Tailscale, ZeroTier and diagnostic CPU profiling |
| `router-vvt` (VVT) | VLESS, VMess and Trojan transport families; DNS/rules/providers/controller; mixed inbound; TUN/redir/TPROXY infrastructure | Every protocol behind `extra-protocols`, and the router exclusions above |

Profiles describe build selection, not universal interoperability, and no profile
name is printed by the binary. Select a build that supports **every** protocol in
the config and every provider entry; VVT does not silently discard unsupported
entries. `router` and VVT must be built with `--no-default-features`; additive
features can change the effective result. `murmur -v` prints the target OS and
architecture, a `Protocol set:` line and the `Use tags:` list; the running
`/version` response reports the same choice as `protocol-set`. The field has only
two values: `full` for the default **and** for `router`, `vvt` for `router-vvt`.
A bundle named `router` whose `-v` says `full` therefore matches this table;
`-v` does not reveal ELF class, endianness or the floating-point ABI. VLESS, VMess
and Trojan belong to the base protocol set, so a `router` build carries them and
`extra-protocols` adds the remaining optional transports (TUIC, Hysteria2,
SSR/Shadowsocks variants, AnyTLS and others). VVT's established update asset is
`murmur-linux-arm64-vvt-<version>.gz` for non-Android Linux ARM64 musl. Do not
assume a corresponding MIPS/ARM32 download exists — none is published; on MIPSEL
use a full or `router` artifact for a VLESS/VMess/Trojan subscription, and if the
supplied artifact is a VVT-only build for another architecture, stop as below
rather than renaming it. The reduced updater rejects unsupported targets. No
automatic upgrade is needed for this installation.

The demonstrated router target is static Linux AArch64 musl on OpenWrt. This is
not evidence that a KN-1810, MIPS/MIPSEL, ARM32 or any particular KeeneticOS kernel
can run it. If inspection reports a different target and no matching verified
artifact is supplied, **stop installation**: obtain/build that exact target and
validate it on compatible hardware first. Changing filename, forcing execution
or flashing firmware is not a compatibility fix.

On a trusted workstation, check the compressed download's supplied checksum,
decompress into staging, then inspect the resulting ELF:

```sh
sha256sum -c artifact.sha256
gzip -dc artifact.gz > murmur.new
file murmur.new
readelf -h -l -d -A murmur.new
sha256sum murmur.new
```

Ensure class, machine, endian and ABI match the inventory. A promised static
artifact must not need an ELF interpreter or shared libraries; reject unexpected
build-host paths. Verify the uncompressed checksum again after transfer. Only
then mark it executable and run `murmur.new -v` on the router. `Exec format error`,
an absent required loader, `Illegal instruction` or unsupported protocol is a
stop condition, not a reason to try random assets. Leave the old binary untouched.

**Delivery.** Transfer over the SSH channel you already use, or download on the
device from the same URL. `sftp` needs an `sftp-server` binary that a router's
Dropbear server often lacks, so `sftp` and Paramiko fail during negotiation rather
than at login; stock firmware usually has no `scp`, while Entware may install one
under `/opt/bin`. `wget` and `curl` likewise sit under different prefixes. Pick a
path only after the §1 probe, and verify both digests:

```sh
mkdir -p /tmp/murmur-stage && cd /tmp/murmur-stage || exit 1
curl -fsSL --max-time 300 -o murmur.tar.gz "ASSET_URL_FROM_TRUSTED_CHANNEL"
sha256sum murmur.tar.gz   # must equal the digest from the trusted channel
tar xzf murmur.tar.gz
sha256sum murmur          # must equal the SHA256SUMS entry inside the archive
```

Use `wget -O` where `curl` is absent. If `sha256sum` is absent, do not skip the
check: Entware may ship it in a separate package as `/opt/bin/sha256sum`, and not
every BusyBox build carries the applet, so verify on the workstation instead and
transfer only over an authenticated channel. Never fetch over plain HTTP, from a
third-party mirror, or with a token in the URL.

**Header check without `file`/`readelf`.** When those tools are missing on the
device, do the full inspection on the trusted workstation before transfer. On the
device only a coarse check is possible, and `od -An`/`od -tx1` belong to GNU and
desktop-BusyBox builds; a plain BusyBox `od` accepts just `-abcdeFfhiloxsv`, where
the octal byte form keeps positions unambiguous:

```sh
head -c 20 murmur | od -b
# 0000000 177 105 114 106 001 001 001 000 000 000 000 000 000 000 000 000
# 0000020 000 000 010 000
```

Bytes 1-4 read `\x7fELF` (`177 105 114 106`); byte 5 is `001` for ELF32 and `002`
for ELF64; byte 6 is `001` for little-endian and `002` for big-endian; bytes 19-20
are `e_machine` in that endianness — `076 000` x86-64, `267 000` AArch64,
`010 000` MIPS little-endian, `000 010` MIPS big-endian. The sample above is
MIPSEL. If `od` is missing too, stop guessing: the remaining evidence is the
digest plus a successful `-v`, which prints OS and architecture but not class,
endianness or ABI.

## 3. Preserve recovery before installation

Keep a second, independently opened SSH session over a known management path and
physical/console or management-UI access. Check SSH host keys. Use key-based access
where already configured; remove factory credentials through the normal device
procedure, separately from network changes. Never open SSH or the controller to
WAN to simplify setup.

Create a private, persistent backup directory (`umask 077`, mode 0700), copy it
off-device securely, and record a change manifest. It must list every path to be
created/overwritten, original ownership/mode/checksum, existing service enabled
state and intended inverse operation. Back up the existing binary/config/provider
cache/service files before touching them. Preserve firewall, routes/rules, DNS,
DHCP and firmware configuration locally, even for an initially proxy-only setup.
On OpenWrt, `sysupgrade -b BACKUP.tar.gz` makes a configuration backup; also inspect
its coverage and copy nonstandard files separately. On Keenetic, export the
startup configuration through the documented management interface and separately
back up Entware files. A text dump is evidence, not necessarily a restorable backup.

Write a root-owned mode-0700 `rollback.sh` in the backup directory **before**
applying changes. It must contain concrete commands for this attempt, in order:

1. Stop only the new murmur service/process and undo its newly enabled boot hook.
2. Remove only this attempt's interception rules, policy rules/routes and DNS/DHCP
   changes; restore changed settings from the manifest using their actual owner.
3. Restore overwritten files with their original modes/owners. Remove only files
   recorded as newly created; retain backups and logs.
4. Restore the previous service's exact enabled/running state and check SSH, DNS
   and the previous Internet path.

For a fresh loopback-only install, there are no firewall/DNS/routes to undo. For
an upgrade, restoring the old binary without its config and service state is not
complete rollback. Never flush the ruleset, restore an unrelated full snapshot
on top of concurrent changes, use `killall` on shared services, or replace the
router's whole network/firewall configuration.

Arm a detached timer immediately before each risky stage. `B` must be the
absolute, unique backup directory and the reviewed rollback script must already be
complete. `nohup` and `setsid` are not guaranteed on BusyBox or Entware, so choose
the mechanism by probe and stop when neither exists:

```sh
: "${B:?Set B to the private backup directory}"
test -x "$B/rollback.sh" || exit 1
rm -f "$B/timer.pid"
touch "$B/armed"
TIMER='sleep 300; if test -f "$1/armed"; then sh "$1/rollback.sh" >"$1/rollback.log" 2>&1; fi'
if command -v nohup >/dev/null 2>&1; then
    nohup sh -c "$TIMER" sh "$B" </dev/null >"$B/timer.log" 2>&1 &
    printf '%s\n' "$!" > "$B/timer.pid"
elif command -v start-stop-daemon >/dev/null 2>&1; then
    start-stop-daemon -S -q -b -m -p "$B/timer.pid" -x /bin/sh \
        -O "$B/timer.log" -- -c "$TIMER" sh "$B" || exit 1
else
    echo "no nohup or start-stop-daemon available" >&2
    exit 1
fi
```

Do not drop `-p` from the `start-stop-daemon` branch: without a pidfile it matches
every running `/bin/sh`, including `rc.unslung` during boot, and silently declines
to start. With `-p` the match is the recorded PID, `-m` writes that pidfile and
`-O` appends both output streams; `-O` requires `-b` and an absolute path and is
missing from older `start-stop-daemon` builds, so verify that the branch really
detached and read the timer PID from `$B/timer.pid`, not from `$!`.

First test the same timer mechanism with a short delay and a harmless marker,
confirm the PID recorded in `$B/timer.pid` is alive, disconnect that test SSH
session and confirm the marker from another session.
Do not test the real rollback by accidentally restoring a live network. Do not
proceed if detachment cannot be demonstrated. Cancel the real timer with
`rm "$B/armed"` only after checks from a fresh SSH connection and the relevant
LAN client succeed, comfortably before expiry. If time expires or rollback has
started, stop making changes and inspect its result. This timer does **not**
survive reboot; do not reboot a risky topology without console recovery or a
separately verified boot-time rollback mechanism.

## 4. Start a separate manual proxy

Choose unused ports; the examples use mixed TCP/SOCKS port **17890**, controller
**19090** and optional DNS **1053**. Existing mihomo stays running on its original
ports, config directory, cache, interface names and routing marks. Never point
both processes at the same mutable home/cache or share transparent interception.
For the first pass, change no firewall, DNS, DHCP, routes or existing service.

Example persistent locations (use only after checking mount capacity and options):

| Platform | Binary | Private working directory |
| --- | --- | --- |
| OpenWrt | `/usr/bin/murmur` | `/etc/murmur` |
| KeeneticOS + Entware | `/opt/bin/murmur` | `/opt/etc/murmur` |

Transfer the verified binary to the chosen filesystem, stage it alongside the
final path and rename only after verification/backups. Do not overwrite a running
executable in place. Set the binary executable and the private directory to 0700;
config, provider caches and secret-bearing files should be 0600.

Save this minimal **direct-only** baseline as `config.yaml` in that directory.
Replace the controller-secret placeholder with a locally generated unpredictable
secret. `openssl rand -hex 32` works where `openssl` exists; BusyBox and Entware
often lack it and have no `base64` applet either, but BusyBox `hexdump` prints the
same value:

```sh
head -c 32 /dev/urandom | hexdump -v -e '/1 "%02x"'; echo
```

Probe both tools from §1 and generate on a trusted machine when neither exists.
Do not paste the secret into chat, and do not build a command line that contains
it: `ps` shows arguments, so `sed -i "s/…/$secret/"` leaks it into the process
list. Edit the protected file through the channel you trust.

This config does not prove an upstream proxy works and does not proxy the LAN:

```yaml
mixed-port: 17890
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:19090
secret: "REPLACE_WITH_LOCAL_RANDOM_SECRET"
iptables:
  enable: false
tun:
  enable: false
dns:
  enable: false
rules:
  - MATCH,DIRECT
```

Define `BIN` and `HOME_DIR` as the chosen absolute binary and working directory.
Validate, then run in the foreground of a separate session:

```sh
"$BIN" -t -d "$HOME_DIR" -f "$HOME_DIR/config.yaml"
"$BIN" -d "$HOME_DIR" -f "$HOME_DIR/config.yaml"
```

`-t` validates configuration and exits; it does not prove socket binding, device
creation, provider readiness or connectivity. Observe the live process and logs,
then check its exact listeners. From the router (or an SSH-forwarded workstation):

```sh
curl --fail --show-error --max-time 20 --noproxy '' --proxy http://127.0.0.1:17890 https://example.com/
curl --fail --show-error --max-time 20 --noproxy '' --proxy socks5h://127.0.0.1:17890 https://example.com/
```

Use an owner-approved reachable HTTPS origin if this example is blocked; expect
its real status/body, not merely a TCP connect. Do not disable TLS verification.
Stop the foreground instance with Ctrl-C before starting a service. Any staged
background process must be stopped by its verified PID/executable, not by name.

### Add the subscription, without importing its network settings

Obtain a trusted subscription privately. Never send the credential-bearing URL
to an LLM, put it on a command line, or publish cached nodes. Insert it locally in
the protected config. Require the provider's supported payload format (for
example Clash YAML with a top-level `proxies:` list); do not assume arbitrary HTML,
a control-panel URL or another core's full config is a usable provider.

Merge these sections into the baseline, **replacing** its `rules` section:

```yaml
proxy-providers:
  subscription:
    type: http
    url: "https://subscription.example.invalid/REPLACE_LOCALLY"
    path: ./providers/subscription.yaml
    interval: 3600
    health-check:
      enable: true
      url: https://example.com/
      interval: 300
      timeout: 5000
      expected-status: 200
proxy-groups:
  - name: PROXY
    type: select
    use:
      - subscription
rules:
  - MATCH,PROXY
```

The `.invalid` URL intentionally cannot work until replaced. Create the private
`providers` directory. Do not add DIRECT as a fallback just to make checks green.
Keep server TLS verification enabled; enter protocol-specific SNI, UUID, public
keys and transport options exactly as provided. An unsupported provider entry
requires another artifact or an explicitly approved provider change, not silently
dropping the entry. Protect any manual proxy credentials the same way.

Validate and restart the isolated instance. Wait for provider initialization,
confirm that the expected node count and protocols loaded, and explicitly select
a node in `PROXY` via a trusted controller client. Keep controller access on
loopback, optionally through SSH local forwarding; authenticate with the secret.
For CLI API queries, use a mode-0600 curl config file containing the Authorization
header, not a literal token in shell arguments. Query `/version`, `/proxies` and
`/providers/proxies`; inspect `/connections` during traffic to confirm the chosen
chain. Redact these responses before sharing. A green delay number or HTTP 204
reload response alone is not proof of success: inspect logs and exercise traffic.

For a controller-only CLI workflow, locally create `$HOME_DIR/controller.curl`
with mode 0600 in the private directory. Edit its contents in a trusted editor,
inserting the same secret as `config.yaml` immediately after `Bearer ` inside
the quotes below; do not generate a shell command containing that secret:

```text
header = "Authorization: Bearer "
noproxy = "*"
connect-timeout = 5
max-time = 15
fail
silent
show-error
```

Query only the loopback controller with this file. `-q` must be the first curl
argument to ignore an unrelated default curl config; do not add redirects,
verbose output or tracing to these authenticated requests:

```sh
curl -q --config "$HOME_DIR/controller.curl" http://127.0.0.1:19090/version
curl -q --config "$HOME_DIR/controller.curl" http://127.0.0.1:19090/providers/proxies
curl -q --config "$HOME_DIR/controller.curl" http://127.0.0.1:19090/proxies/PROXY
```

Choose an exact member name from the group's `all` list. Save this JSON in a
mode-0600 `$HOME_DIR/select-node.json`, replacing the placeholder and correctly
JSON-escaping any quotes or backslashes in the actual node name:

```json
{"name":"EXACT_NODE_NAME_FROM_GROUP"}
```

Select it, then read back the group and confirm its `now` member is that node:

```sh
curl -q --config "$HOME_DIR/controller.curl" --request PUT \
  --header 'Content-Type: application/json' \
  --data-binary "@$HOME_DIR/select-node.json" --write-out 'HTTP %{http_code}\n' \
  http://127.0.0.1:19090/proxies/PROXY
curl -q --config "$HOME_DIR/controller.curl" http://127.0.0.1:19090/proxies/PROXY
curl -q --config "$HOME_DIR/controller.curl" http://127.0.0.1:19090/connections
```

Successful selection returns HTTP 204; HTTP 400 means the selector/name needs
correction, and HTTP 401 means the controller secret is wrong or missing. Readback
confirms selection, not connectivity. Inspect connections while a real request
is active, and repeat selection/readback after restart if it was not preserved.
Keep these files private and remove the temporary selection file when finished.

Repeat both HTTPS requests through the selected upstream, check expected remote
content and, using an owner-approved endpoint, expected egress. Include a negative
control such as a temporary REJECT rule for the exact test domain, verify failure,
then restore the rule and verify recovery. This distinguishes the intended proxy
path from accidental DIRECT success. Provider download/refresh and node health
must remain healthy; a cached list alone does not prove refresh works.

### DNS without a circular dependency

Initially keep the router's resolver untouched and murmur DNS disabled. Verify
that the existing resolver can bootstrap the subscription hostname and proxy
server hostnames without using the new proxy. Resolve clock/CA/DNS problems;
do not bypass certificate checks.

If murmur DNS is needed, first test a loopback-only listener, still with no client
redirection. Replace the baseline `dns` section with this **template**, substituting
an approved reachable numeric upstream address:

```yaml
dns:
  enable: true
  listen: 127.0.0.1:1053
  ipv6: false
  enhanced-mode: redir-host
  nameserver:
    - "UPSTREAM_DNS_IP:53"
```

The numeric address avoids resolving the resolver's own hostname. Confirm that
this upstream does not forward back to murmur. If encrypted DNS is selected,
separately configure and verify bootstrap resolution and certificate validation.
Do not make router DNS depend on a subscription download that itself needs that
DNS or on a proxy server that cannot yet resolve. Test UDP and TCP DNS using an
available client supporting a nonstandard port, such as `dig @127.0.0.1 -p 1053
example.com` and the same command with `+tcp`.

Do not enable fake-IP merely because another config has it: every client receiving
synthetic answers must have the corresponding traffic captured by this same
instance. For an approved fake-IP gateway, avoid real-network address overlap,
exclude local/LAN names as appropriate, preserve its cache intentionally, seed
rule providers before exposing DNS, and disable dnsmasq caching of fake-IP answers.
Do not copy a full subscription's listener/DNS/controller/TUN settings over these
local safety choices.

## 5. Install startup only after foreground checks pass

These are separate platform patterns, not interchangeable installation scripts.
Verify the observed platform files match the cited implementations first. All
scripts and parent directories must be root-owned and not writable by other users.
Do not install over an existing service file without backing it up.

### OpenWrt with procd

For the paths above, create `/etc/init.d/murmur` with mode 0755:

```sh
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
    /usr/bin/murmur -t -d /etc/murmur -f /etc/murmur/config.yaml || return 1
    procd_open_instance
    procd_set_param command /usr/bin/murmur -d /etc/murmur -f /etc/murmur/config.yaml
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param term_timeout 30
    procd_close_instance
}
```

Use `/etc/init.d/murmur start`, `stop` or `restart`; use
`/etc/init.d/murmur enable` only after the service passes the same checks.
`/etc/init.d/murmur disable` undoes persistence. Inspect `logread -e murmur`,
`ubus call service list '{"name":"murmur"}'`, listeners and real requests. A
respawning process is a failure to diagnose, not readiness. Log buffering is not
a durable audit trail; copy bounded, redacted diagnostics to protected storage
when needed. If using external storage, add a verified mount dependency rather
than assuming START=99 guarantees it is mounted.

### KeeneticOS with an existing Entware installation

Verify the configured OPKG init path actually invokes the installed
`/opt/etc/init.d/rc.unslung` after `/opt` is mounted. `rc.unslung` sources every
executable `S*` file and passes the action as `$1`, so inside a sourced service
script `$0` is `rc.unslung`: never `exit` and never re-invoke `$0` there, or the
whole service set is affected. Do not run `rc.unslung restart`
for this task: it affects other Entware services, potentially including SSH.
The following pattern relies on the installed `rc.func` implementing `ENABLED`,
`PROCS`, `ARGS` and `start|stop|check` as in the primary source linked below.

Only if there is exactly one murmur process to own, create
`/opt/etc/init.d/S99murmur` with mode 0755:

```sh
#!/bin/sh
ENABLED=yes
PROCS=murmur
ARGS="-d /opt/etc/murmur -f /opt/etc/murmur/config.yaml"
PREARGS=""
DESC="murmur proxy"
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
. /opt/etc/init.d/rc.func
```

Run the explicit `-t` check before every start/restart. Control only this service
with `/opt/etc/init.d/S99murmur start`, `stop`, `restart` or `check`. Its helper
uses process-name detection/stopping; do not use it for multiple murmur instances.
Its `check` tests presence, not functional health, and it is not a procd-style
supervisor. For removal, stop it first, then set `ENABLED=no` or remove only the
newly installed script as recorded in the manifest.

The cited helper discards daemon stdout/stderr and has no restart, so service
start/stop messages are not runtime logs and a crash leaves the service down.
Capture the foreground run's output in a protected, size-bounded temporary file
for diagnosis, or observe the authenticated controller `/logs` stream through a
compatible client. murmur has no log-file flag; do not invent one.

If persistent runtime logs and crash restart are required, make this one service
own its process with `start-stop-daemon` instead of `rc.func`. Verify the applet
exists (§1) and that it supports `-O`, create `/opt/var/log` (`-O` creates the
file, not its directory), then replace the script above with this source-safe one:

```sh
#!/bin/sh
# /opt/etc/init.d/S99murmur, mode 0755, root-owned; sourced by rc.unslung.
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
DIR=/opt/etc/murmur
BIN=/opt/bin/murmur
LOG=/opt/var/log/murmur.log
start() {
    "$BIN" -t -d "$DIR" -f "$DIR/config.yaml" || return 1
    start-stop-daemon -S -q -b -x "$BIN" -O "$LOG" -- -d "$DIR" -f "$DIR/config.yaml"
}
stop() {
    start-stop-daemon -K -q -x "$BIN"
}
case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    *) echo "usage: S99murmur {start|stop|restart}" >&2 ;;
esac
```

`-x` must name the real executable, not a symlink: start and stop matching
compares `/proc/<pid>/exe`. `-O` opens the log with `O_CREAT|O_APPEND` and
redirects both output streams before exec, so truncate a live log with
`: > "$LOG"` instead of deleting it. Test start, stop, log content and a killed
process on the device before claiming supervision.

Entware's cron reads `/opt/etc/crontabs/root`; confirm `crond` is installed and
running before relying on it. A one-minute watchdog only needs the idempotent
start:

```
* * * * * /opt/etc/init.d/S99murmur start >/dev/null 2>&1
```

Cron receives a minimal `PATH`, so use absolute paths there. Detection latency is
up to a minute, a `pidof murmur` guard is weaker than the service's own check and
matches a second, manually started instance, and cron does not rotate logs: bound
the file yourself. Older `start-stop-daemon` builds lack `-O`; without it, keep
the `rc.func` script and capture output separately rather than claiming
persistent logs.

Reboot testing must confirm `/opt` mounts and this one service starts without
manual SSH login. `rc.func` reports success through `logger` as
`Started $DESC from $CALLER.`, so the device log is evidence that boot reached the
service; the custom script above should log the same message if that evidence is
required. Entware presence alone does not prove boot integration.

## 6. LAN gateway: a separate, explicitly approved change

Do not promise all-router compatibility or paste generic transparent-proxy rules.
Present the owner with an interface/traffic-flow diagram, exact affected clients,
management bypass, IPv4/IPv6 scope, UDP policy, DNS path, fail-open/fail-closed
policy and the proposed inverse changes. Get approval before changing topology.
Keep an initial canary client; do not immediately capture the whole LAN.

Required evidence depends on the chosen path:

| Path | Evidence required before enabling |
| --- | --- |
| Manual LAN proxy | Deliberately bind only the intended LAN address, authenticate/restrict clients, allow its port only from approved LAN; keep controller loopback |
| TCP redir | Kernel/backend redirect support, original-destination handling and an owned interception chain; this alone does not capture UDP |
| TCP/UDP TPROXY | Kernel transparent-proxy/socket support, backend-compatible rules, a free capture mark, matching policy route/table and a distinct outbound bypass mark |
| TUN | Working `/dev/net/tun` and permissions/CAP_NET_ADMIN, successful device creation, explicit addresses/routes, upstream/management bypass and confirmed forwarding/firewall behavior |

Installing userspace tools does not add missing firmware kernel features. On
OpenWrt/fw4, confirm matching kernel modules (including `kmod-nft-tproxy` for that
path) from the exact firmware package feed. Never force-install a mismatched
kernel package. On Keenetic, verify its kernel capabilities and supported
persistent integration hooks separately; OpenWrt package names and fw4 includes
are not a solution. If the hooks/modules or a safe bypass cannot be verified,
stop at the already working manual proxy and state the missing prerequisite.

When an external firewall manager owns capture, keep `iptables.enable: false`.
Do not run two interception owners. Murmur's built-in iptables path is not an
automatic fw4/Keenetic integration; it can modify rules and abort on setup failure.
Avoid full ruleset replacement, default-route replacement and broad OUTPUT
capture. Exclude the proxy's own outbound traffic, management path, required local
networks, provider/DNS bootstrap paths and existing tunnels from recursive capture.
Use unique route tables, marks, chain names and TUN device names, checked against
all existing services. Preserve those services' DNS and forwarding policy.

**TUN limitations matter even if `-t` succeeds.** Runtime TUN failure can be logged
while the rest of murmur starts and its stored TUN config becomes disabled.
Confirm the device, installed routes, runtime config and real traffic. Do not
infer TUN success from a live controller. Automatic routes can add a default
route; do not enable `auto-route` without a reviewed bypass design. The currently
implemented TUN stack is smoltcp even under the `gvisor`/`mips` labels, not gVisor.
Unsupported options include `stack: system`/`mixed`, `dns-hijack`, `auto-redirect`,
`auto-detect-interface`, `strict-route`, `gso`, endpoint-independent NAT, timeout
and UID/interface/port/package/MAC filter overrides, route-set/exclusion options,
and iproute2-index/redirect-mark options. `disable-icmp-forwarding` must be true.
Do not present these as automatic LAN integration features.

For an IPv4-only gateway, `ipv6: false` in murmur does **not** establish a LAN IPv6
leak policy. Decide explicitly whether IPv6 is routed through a verified IPv6 path
or blocked for the affected clients with owner consent; account for RA/DHCPv6 and
existing IPv6 routes. Do not silently leave native IPv6 bypassing a promised full
proxy. Test UDP through the actual chosen proxy transport, not only a DNS query
to the router. Include a controlled UDP request/reply and relevant large-datagram
or QUIC traffic; ping or HTTP CONNECT does not prove UDP forwarding.

Only persist firewall/DNS/routing changes using hooks verified for the observed
firmware, after runtime canary checks and rollback checks pass. Keep the manifest
and timed rollback current for each additional stage. This guide deliberately
has no universal firewall script: absent that device-specific evidence, transparent
gateway setup is blocked, not complete.

## 7. Readiness, reboot and handoff

Report each item as **passed**, **failed** or **not tested**, with redacted evidence:

- Artifact checksum/version/architecture match and `-v` reports the expected
  `Protocol set:` and tags; config-test passes and no unsupported-protocol or
  provider errors remain.
- Exactly the intended instance and listeners exist; controller is loopback-only,
  WAN cannot access proxy/DNS/controller, existing mihomo remains unaffected.
- Real HTTP and SOCKS HTTPS requests work through the selected upstream; expected
  content/egress, selected chain, negative control and recovery are observed.
- Provider initialization and refresh work; no bootstrap DNS loop; DNS UDP/TCP and
  UDP/IPv6 application paths are checked where promised.
- For gateway scope, a real LAN canary without application proxy settings follows
  the intended path, management remains reachable, and bypass/leak policy is tested.
- Startup persistence, logs, controlled stop/start and recovery work. Memory/storage
  remain sufficient under representative load, without OOM or restart loops.

After approval and safe recovery arrangements, reboot once. Open a fresh SSH
connection, confirm storage mounts, only the intended service starts, controller
binding is unchanged, providers become ready, and repeat the relevant router/LAN
traffic and DNS checks. Reboot success means observed traffic after reboot, not
an enabled symlink or a running PID. Do not reboot to test recovery while relying
on the in-memory timer from section 3.

Useful failure distinctions: bind failure means inspect port ownership; provider
401/403 means resolve credentials privately; artifact 404 means resolve access or
availability; TLS errors mean check clock, CA and SNI; working IPs but failing
names mean inspect DNS/bootstrap; TCP success with UDP failure means investigate
transport, capture and MTU separately; a TUN warning with a healthy controller
means the gateway is not proven. Never hide these with DIRECT fallback, disabled
TLS checks or a narrower success claim.

Finish by giving the owner the installed paths, exact profile/version/checksum,
chosen ports and traffic scope, service start/stop/log instructions, protected
backup location, exact rollback command, completed checks and remaining blockers.
Do not include actual secrets in that report. ARM64 OpenWrt testing is evidence
for that tested setup, not a compatibility certification for every router,
transport variant or KeeneticOS firmware.

## Public primary references

These explain platform tools; none is a murmur download or a substitute for local
inspection. The murmur behavior described above reflects its source/runbook state
on 2026-10-25; require matching artifact evidence for later versions.

- [OpenWrt procd init scripts](https://openwrt.org/docs/guide-developer/procd-init-scripts)
  and [init scripts](https://openwrt.org/docs/techref/initscripts).
- [OpenWrt configuration backup](https://openwrt.org/docs/guide-user/troubleshooting/backup_restore).
- [Keenetic Entware installation and OPKG boot/SSH behavior](https://help.keenetic.com/hc/en-us/articles/360021214160-Installing-the-Entware-repository-on-a-USB-drive).
  The vendor may redirect this to another model's manual: select the exact model
  before using any installer or architecture advice.
- [Entware rc.func source](https://github.com/Entware/rtndev/blob/master/entware-opt/files/rc.func)
  and [rc.unslung source](https://github.com/Entware/rtndev/blob/master/entware-opt/files/rc.unslung).
  Compare the installed version, especially process matching and log handling.
- [Linux transparent proxy requirements](https://www.kernel.org/doc/html/v5.17/networking/tproxy.html)
  and [TUN/TAP requirements](https://www.kernel.org/doc/html/v6.1/networking/tuntap.html).
- [curl command reference](https://curl.se/docs/manpage.html),
  [GNU readelf](https://sourceware.org/binutils/docs/binutils/readelf.html),
  [BusyBox applets](https://busybox.net/downloads/BusyBox.html) and
  [OpenSSH forwarding](https://man.openbsd.org/ssh).
