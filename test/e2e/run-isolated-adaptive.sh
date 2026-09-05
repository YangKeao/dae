#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
UPSTREAM_IMAGE=${UPSTREAM_IMAGE:-daeuniverse/dae:20260220}
CANDIDATE_IMAGE=${CANDIDATE_IMAGE:-dae-adaptive-e2e:local}

WAN_NETWORK=dae-e2e-wan-20260905
LAN_NETWORK=dae-e2e-lan-20260905
ROUTER=dae-e2e-router
TARGET=dae-e2e-target
DEFAULT_SLOW=dae-e2e-default-slow
DEFAULT_FAST=dae-e2e-default-fast
AI_SLOW=dae-e2e-ai-slow
AI_FAST=dae-e2e-ai-fast
DEFAULT_CLIENT=dae-e2e-client-default
AI_CLIENT=dae-e2e-client-ai
CERT_DIR=$(mktemp -d /tmp/dae-isolated-e2e-certs.XXXXXX)

CONTAINERS=(
    "$DEFAULT_CLIENT" "$AI_CLIENT" "$ROUTER" "$TARGET"
    "$DEFAULT_SLOW" "$DEFAULT_FAST" "$AI_SLOW" "$AI_FAST"
)

cleanup_runtime() {
    set +e
    for container in "${CONTAINERS[@]}"; do
        docker container kill "$container" >/dev/null 2>&1
    done
    for container in "${CONTAINERS[@]}"; do
        docker container remove "$container" >/dev/null 2>&1
    done
    docker network remove "$LAN_NETWORK" >/dev/null 2>&1
    docker network remove "$WAN_NETWORK" >/dev/null 2>&1
    gio trash "$CERT_DIR" >/dev/null 2>&1
}
trap cleanup_runtime EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    if docker container inspect "$ROUTER" >/dev/null 2>&1; then
        printf '%s\n' '--- dae router log (tail) ---' >&2
        docker logs --tail 120 "$ROUTER" >&2 || true
        printf '%s\n' '--- dae router network ---' >&2
        docker exec "$ROUTER" ip -o address show >&2 || true
        docker exec "$ROUTER" ip route >&2 || true
        docker exec "$ROUTER" sysctl net.ipv4.ip_forward >&2 || true
    fi
    local client
    for client in "$DEFAULT_CLIENT" "$AI_CLIENT"; do
        if docker container inspect "$client" >/dev/null 2>&1; then
            printf '%s\n' "--- $client network ---" >&2
            docker exec "$client" ip -o address show >&2 || true
            docker exec "$client" ip route >&2 || true
            docker exec "$client" cat /etc/hosts >&2 || true
        fi
    done
    local proxy
    for proxy in "$DEFAULT_SLOW" "$DEFAULT_FAST" "$AI_SLOW" "$AI_FAST"; do
        if docker container inspect "$proxy" >/dev/null 2>&1; then
            printf '%s\n' "--- $proxy log (tail) ---" >&2
            docker logs --tail 30 "$proxy" >&2 || true
        fi
    done
    exit 1
}

assert_contains() {
    local text=$1
    local pattern=$2
    local message=$3
    grep -Eq -- "$pattern" <<<"$text" || fail "$message"
}

assert_not_contains() {
    local text=$1
    local pattern=$2
    local message=$3
    if grep -Eq -- "$pattern" <<<"$text"; then
        fail "$message"
    fi
}

assert_clean_start() {
    local container
    for container in "${CONTAINERS[@]}"; do
        if docker container inspect "$container" >/dev/null 2>&1; then
            fail "container name already exists: $container"
        fi
    done
    if docker network inspect "$WAN_NETWORK" >/dev/null 2>&1; then
        fail "network name already exists: $WAN_NETWORK"
    fi
    if docker network inspect "$LAN_NETWORK" >/dev/null 2>&1; then
        fail "network name already exists: $LAN_NETWORK"
    fi
}

make_certificate() {
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj '/CN=target.test' \
        -addext 'subjectAltName=DNS:target.test,IP:10.231.50.20' \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" >/dev/null 2>&1
}

start_proxy() {
    local name=$1
    local address=$2
    local delay_ms=$3
    local node_name=$4
    docker run --detach \
        --name "$name" \
        --network "$WAN_NETWORK" \
        --ip "$address" \
        --add-host target.test:10.231.50.20 \
        --env "NODE_NAME=$node_name" \
        --env "CONNECT_DELAY_MS=$delay_ms" \
        --volume "$SCRIPT_DIR/socks5.py:/app/socks5.py:ro" \
        python:3.13-alpine python /app/socks5.py >/dev/null
}

start_backends() {
    docker network create --driver bridge --subnet 10.231.50.0/24 "$WAN_NETWORK" >/dev/null
    docker network create --driver bridge --internal --subnet 10.231.51.0/24 "$LAN_NETWORK" >/dev/null

    docker run --detach \
        --name "$TARGET" \
        --network "$WAN_NETWORK" \
        --ip 10.231.50.20 \
        --env CERT_FILE=/certs/server.crt \
        --env KEY_FILE=/certs/server.key \
        --volume "$SCRIPT_DIR/https_server.py:/app/https_server.py:ro" \
        --volume "$CERT_DIR:/certs:ro" \
        python:3.13-alpine python /app/https_server.py >/dev/null

    start_proxy "$DEFAULT_SLOW" 10.231.50.11 180 default_slow
    start_proxy "$DEFAULT_FAST" 10.231.50.12 20 default_fast
    start_proxy "$AI_SLOW" 10.231.50.13 160 ai_slow
    start_proxy "$AI_FAST" 10.231.50.14 30 ai_fast
    sleep 1

    local container
    for container in "$TARGET" "$DEFAULT_SLOW" "$DEFAULT_FAST" "$AI_SLOW" "$AI_FAST"; do
        [ "$(docker container inspect --format '{{.State.Running}}' "$container")" = true ] || \
            fail "backend did not start: $container"
    done
}

stop_router_and_clients() {
    set +e
    for container in "$DEFAULT_CLIENT" "$AI_CLIENT" "$ROUTER"; do
        docker container kill "$container" >/dev/null 2>&1
    done
    for container in "$DEFAULT_CLIENT" "$AI_CLIENT" "$ROUTER"; do
        docker container remove "$container" >/dev/null 2>&1
    done
    set -e
}

start_router_and_clients() {
    local image=$1
    local config=$2

    docker create \
        --privileged \
        --name "$ROUTER" \
        --network "$WAN_NETWORK" \
        --ip 10.231.50.2 \
        --tmpfs /sys/fs/bpf:rw \
        --env SSL_CERT_FILE=/lab/server.crt \
        --volume "$SCRIPT_DIR/$config:/lab/config.template:ro" \
        --volume "$CERT_DIR/server.crt:/lab/server.crt:ro" \
        --entrypoint /bin/sh \
        "$image" \
        -c 'lan_if=$(ip -o -4 address show | awk '\''$4 == "10.231.51.2/24" { print $2; exit }'\''); [ -n "$lan_if" ] || exit 20; sed "s/LAN_INTERFACE_PLACEHOLDER/$lan_if/" /lab/config.template > /tmp/config.dae; chmod 0600 /tmp/config.dae; mount -t bpf bpf /sys/fs/bpf && exec dae run -c /tmp/config.dae' >/dev/null
    docker network connect --ip 10.231.51.2 "$LAN_NETWORK" "$ROUTER"
    docker container start "$ROUTER" >/dev/null

    local ready=false
    local attempt
    for ((attempt = 1; attempt <= 60; attempt++)); do
        if docker logs "$ROUTER" 2>&1 | grep -q 'Routing match set len:'; then
            ready=true
            break
        fi
        if [ "$(docker container inspect --format '{{.State.Running}}' "$ROUTER")" != true ]; then
            break
        fi
        sleep 0.25
    done
    [ "$ready" = true ] || fail "dae router did not become ready"
    docker exec "$ROUTER" ip -o -4 address show | grep -q '10.231.51.2/24' || \
        fail 'dae LAN address is missing'

    docker create \
        --name "$DEFAULT_CLIENT" \
        --cap-add NET_ADMIN \
        --network "$LAN_NETWORK" \
        --ip 10.231.51.10 \
        --add-host target.test:10.231.50.20 \
        alpine:3.22 sleep infinity >/dev/null
    docker create \
        --name "$AI_CLIENT" \
        --cap-add NET_ADMIN \
        --network "$LAN_NETWORK" \
        --ip 10.231.51.11 \
        --add-host target.test:10.231.50.20 \
        alpine:3.22 sleep infinity >/dev/null
    docker container start "$DEFAULT_CLIENT" "$AI_CLIENT" >/dev/null
    docker exec "$DEFAULT_CLIENT" ip route replace default via 10.231.51.2
    docker exec "$AI_CLIENT" ip route replace default via 10.231.51.2
    sleep 1

    if [ "$(docker container inspect --format '{{.State.Running}}' "$ROUTER")" != true ]; then
        docker logs "$ROUTER" >&2
        fail "dae router exited"
    fi
}

request_once() {
    local client=$1
    local body
    if ! body=$(docker exec "$client" wget -q -T 10 -t 1 -O - --no-check-certificate https://target.test/); then
        printf 'request failed through %s\n' "$client" >&2
        return 1
    fi
    if [ "$body" != 'dae isolated e2e ok' ]; then
        printf 'unexpected HTTPS response through %s: %s\n' "$client" "$body" >&2
        return 1
    fi
}

request_many() {
    local client=$1
    local count=$2
    local attempt
    for ((attempt = 1; attempt <= count; attempt++)); do
        request_once "$client"
    done
}

request_both_groups() {
    local count=$1
    local default_pid
    local ai_pid
    request_many "$DEFAULT_CLIENT" "$count" &
    default_pid=$!
    request_many "$AI_CLIENT" "$count" &
    ai_pid=$!
    if ! wait "$default_pid"; then
        fail "default client request batch failed"
    fi
    if ! wait "$ai_pid"; then
        fail "ai client request batch failed"
    fi
}

assert_group_isolation() {
    local logs=$1
    assert_not_contains "$logs" 'dialer="?ai_[^" ]*"? .*outbound=default' \
        'default traffic crossed into an ai dialer'
    assert_not_contains "$logs" 'dialer="?default_[^" ]*"? .*outbound=ai' \
        'ai traffic crossed into a default dialer'
}

run_baseline_case() {
    local label=$1
    local image=$2
    printf 'CASE %s: image=%s, adaptive=off\n' "$label" "$image"
    stop_router_and_clients
    start_router_and_clients "$image" proxy-base.dae
    request_both_groups 3

    local logs
    logs=$(docker logs "$ROUTER" 2>&1)
    assert_contains "$logs" 'dialer="?default_[^" ]*"? .*outbound=default' \
        "$label did not route default traffic through the default group"
    assert_contains "$logs" 'dialer="?ai_[^" ]*"? .*outbound=ai' \
        "$label did not route ai traffic through the ai group"
    assert_group_isolation "$logs"
    printf 'PASS %s: default=3/3 ai=3/3 group_isolation=ok\n' "$label"
}

run_adaptive_case() {
    printf 'CASE candidate-adaptive: image=%s, adaptive=enforce\n' "$CANDIDATE_IMAGE"
    stop_router_and_clients
    start_router_and_clients "$CANDIDATE_IMAGE" proxy-adaptive.dae

    request_both_groups 3
    sleep 4

    local metrics
    metrics=$(docker exec "$ROUTER" wget -q -O - http://127.0.0.1:2024/metrics)
    assert_contains "$metrics" 'dae_adaptive_target_connections\{group="default",hot="true",mode="enforce",network="tcp4",target="target.test:443"\} [3-9][0-9]*' \
        'default target did not become hot'
    assert_contains "$metrics" 'dae_adaptive_target_connections\{group="ai",hot="true",mode="enforce",network="tcp4",target="target.test:443"\} [3-9][0-9]*' \
        'ai target did not become hot'
    assert_contains "$metrics" 'dae_adaptive_recommended_dialer_info\{dialer="default_fast",group="default"[^}]*\} 1' \
        'default group did not recommend default_fast'
    assert_contains "$metrics" 'dae_adaptive_recommended_dialer_info\{dialer="ai_fast",group="ai"[^}]*\} 1' \
        'ai group did not recommend ai_fast'
    assert_not_contains "$metrics" 'dae_adaptive_recommended_dialer_info\{dialer="ai_[^"]*",group="default"' \
        'default group recommended an ai dialer'
    assert_not_contains "$metrics" 'dae_adaptive_recommended_dialer_info\{dialer="default_[^"]*",group="ai"' \
        'ai group recommended a default dialer'

    request_both_groups 5
    local logs
    logs=$(docker logs "$ROUTER" 2>&1)
    assert_contains "$logs" 'adaptive_applied=true .*dialer="?default_fast"? .*outbound=default' \
        'default recommendation was not applied'
    assert_contains "$logs" 'adaptive_applied=true .*dialer="?ai_fast"? .*outbound=ai' \
        'ai recommendation was not applied'
    assert_group_isolation "$logs"
    printf 'PASS candidate-adaptive-selection: default=5/5->default_fast ai=5/5->ai_fast\n'

    docker container kill "$DEFAULT_FAST" >/dev/null
    if ! request_once "$DEFAULT_CLIENT"; then
        fail 'default request did not recover after default_fast stopped'
    fi
    if ! request_once "$AI_CLIENT"; then
        fail 'ai request failed after an unrelated default-group node stopped'
    fi
    sleep 2

    logs=$(docker logs "$ROUTER" 2>&1)
    metrics=$(docker exec "$ROUTER" wget -q -O - http://127.0.0.1:2024/metrics)
    assert_contains "$logs" 'dialer="?default_slow"? .*outbound=default' \
        'default group did not fall back inside its group after default_fast failed'
    assert_contains "$logs" 'dialer="?ai_fast"? .*outbound=ai' \
        'ai group stopped using ai_fast when a default-group node failed'
    assert_contains "$metrics" 'dae_connections_total\{dialer="default_fast",group="default",network="tcp4",result="error"\} [1-9][0-9]*' \
        'default_fast failure was not recorded'
    assert_group_isolation "$logs"
    printf 'PASS candidate-adaptive-failover: default_fast_down->default_slow ai_stays_ai_fast\n'
}

assert_clean_start
make_certificate
start_backends
if [ "${ADAPTIVE_ONLY:-false}" != true ]; then
    run_baseline_case upstream "$UPSTREAM_IMAGE"
    run_baseline_case candidate-with-feature-disabled "$CANDIDATE_IMAGE"
fi
run_adaptive_case
printf 'ALL ISOLATED DAE E2E CASES PASSED\n'
