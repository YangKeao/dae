#!/usr/bin/env bash

set -u

DURATION=${1:-90}
case "$DURATION" in
    ''|*[!0-9]*)
        printf 'usage: %s [capture-seconds]\n' "$0" >&2
        exit 2
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    printf 'run this collector as root\n' >&2
    exit 1
fi

DAE_CONTAINER=${DAE_CONTAINER:-}
if [ -z "$DAE_CONTAINER" ]; then
    DAE_CONTAINER=$(docker ps --filter label=com.docker.compose.service=dae --format '{{.Names}}' | head -n 1)
fi
if [ -z "$DAE_CONTAINER" ] || ! docker inspect "$DAE_CONTAINER" >/dev/null 2>&1; then
    printf 'cannot find the running dae container; set DAE_CONTAINER explicitly\n' >&2
    exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
OUT_DIR=${OUT_DIR:-/root/dae-debug-$STAMP}
mkdir -p "$OUT_DIR"
chmod 0700 "$OUT_DIR"
STARTED_AT=$(date --iso-8601=seconds)

capture() {
    name=$1
    shift
    {
        printf '$'
        printf ' %q' "$@"
        printf '\n\n'
        "$@"
    } >"$OUT_DIR/$name.txt" 2>&1 || true
}

capture_shell() {
    name=$1
    shift
    {
        printf '$ %s\n\n' "$*"
        /bin/sh -c "$*"
    } >"$OUT_DIR/$name.txt" 2>&1 || true
}

{
    printf 'started_at=%s\n' "$STARTED_AT"
    printf 'duration_seconds=%s\n' "$DURATION"
    printf 'dae_container=%s\n' "$DAE_CONTAINER"
    printf 'hostname=%s\n' "$(hostname)"
} >"$OUT_DIR/manifest.txt"

capture uname uname -a
capture docker-version docker version
capture docker-ps docker ps --no-trunc
capture docker-inspect docker inspect "$DAE_CONTAINER" --format 'image={{.Config.Image}} image_id={{.Image}} created={{.Created}} started={{.State.StartedAt}} status={{.State.Status}} pid={{.State.Pid}} network={{.HostConfig.NetworkMode}} privileged={{.HostConfig.Privileged}} restart={{.HostConfig.RestartPolicy.Name}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}}:{{.Mode}};{{end}}'
capture dae-version docker exec "$DAE_CONTAINER" dae --version
capture dae-config-fingerprint docker exec "$DAE_CONTAINER" sh -c 'sha256sum /etc/dae/config.dae; stat -c "mode=%a owner=%u:%g size=%s mtime=%y" /etc/dae/config.dae'
capture ip-address ip -details -statistics address show
capture ip-link ip -details -statistics link show
capture ip-rule ip rule show
capture ip-route-v4 ip -4 route show table all
capture ip-route-v6 ip -6 route show table all
capture bridge-link bridge -details link show
capture sockets-before ss -nputo
capture bpf-files find /sys/fs/bpf/dae -maxdepth 3 -printf '%M %u:%g %s %p\n'
capture dmesg-before dmesg --ctime
capture_shell tc-before 'for dev in $(ls /sys/class/net); do echo "### $dev ingress"; tc -s filter show dev "$dev" ingress; echo "### $dev egress"; tc -s filter show dev "$dev" egress; done'
capture_shell ethtool-drivers 'command -v ethtool >/dev/null || exit 0; for dev in $(ls /sys/class/net); do echo "### $dev"; ethtool -i "$dev" 2>&1; ethtool -k "$dev" 2>&1; done'
capture_shell nft-before 'command -v nft >/dev/null && nft list ruleset'
capture_shell iptables-before 'command -v iptables-save >/dev/null && iptables-save; command -v ip6tables-save >/dev/null && ip6tables-save'

TCPDUMP_PID=
if command -v tcpdump >/dev/null 2>&1; then
    timeout "$DURATION" tcpdump -i any -nn -s 256 -B 8192 -C 64 -W 2 \
        -w "$OUT_DIR/traffic.pcap" '(tcp or icmp or icmp6)' \
        >"$OUT_DIR/tcpdump.txt" 2>&1 &
    TCPDUMP_PID=$!
fi

TRACE_PID=
timeout "$DURATION" docker exec "$DAE_CONTAINER" dae trace -4 -p tcp -P 443 --drop-only \
    >"$OUT_DIR/dae-trace-tcp4-443.txt" 2>&1 &
TRACE_PID=$!

printf '\nCapture is running for %s seconds. From a LAN client, run the printed curl/dig tests now.\n' "$DURATION"
printf 'Do not test only from the router itself; LAN forwarding is the path under investigation.\n\n'

end=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$end" ]; do
    {
        date --iso-8601=ns
        ss -nto state syn-sent
        ss -nto state established
        for url in http://127.0.0.1:2024/metrics http://192.168.1.106:2024/metrics; do
            curl --max-time 2 --silent --show-error "$url" 2>/dev/null && break
        done
    } >>"$OUT_DIR/timeline.txt" 2>&1
    sleep 2
done

[ -z "$TCPDUMP_PID" ] || wait "$TCPDUMP_PID" 2>/dev/null || true
wait "$TRACE_PID" 2>/dev/null || true

capture sockets-after ss -nputo
capture dmesg-after dmesg --ctime
capture_shell tc-after 'for dev in $(ls /sys/class/net); do echo "### $dev ingress"; tc -s filter show dev "$dev" ingress; echo "### $dev egress"; tc -s filter show dev "$dev" egress; done'
docker logs --timestamps --since "$STARTED_AT" "$DAE_CONTAINER" >"$OUT_DIR/dae-container.log" 2>&1 || true

docker exec "$DAE_CONTAINER" sh -c 'cd /tmp && dae sysdump' >"$OUT_DIR/dae-sysdump-command.txt" 2>&1 || true
SYSDUMP=$(docker exec "$DAE_CONTAINER" sh -c 'ls -1t /tmp/dae-sysdump.*.tar.gz 2>/dev/null | head -n 1' 2>/dev/null || true)
if [ -n "$SYSDUMP" ]; then
    docker cp "$DAE_CONTAINER:$SYSDUMP" "$OUT_DIR/" >/dev/null 2>&1 || true
fi

ARCHIVE="$OUT_DIR.tar.gz"
tar -C "$(dirname "$OUT_DIR")" -czf "$ARCHIVE" "$(basename "$OUT_DIR")"
chmod 0600 "$ARCHIVE"
printf '\nCollected: %s\n' "$ARCHIVE"
printf 'The archive excludes dae config contents and Docker environment variables. PCAP still contains endpoint IPs and TLS/DNS metadata.\n'
