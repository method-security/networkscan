#!/usr/bin/env bash
#
# networkscan dependency-bump smoke test.
#
# Purpose: this repo's hand-written test coverage is 24 functions across 5
# files (IPMI framing, a redis query parser, net-error classification). The
# other ~2200 test functions are Fern-generated JSON round-trips under
# generated/. Nothing tests a dependency surface. `go build` passing proves the
# APIs still line up and nothing about runtime behaviour.
#
# The specific reason this script exists: naabu is a LOCKED dependency (see the
# comment on it in go.mod). It cannot be bumped, but it shares its whole
# transitive graph with nuclei -- projectdiscovery/utils, fastdialer,
# retryablehttp-go, mapcidr, gologger. Bumping nuclei moves those versions
# UNDER a pinned naabu. naabu still compiling against them is not evidence that
# it still scans. Section 2 below is that evidence: a real CONNECT scan against
# real local listeners, asserting the open ports are found and a closed one is
# not.
#
# All traffic is to 127.0.0.1. The script makes no external network requests.
#
# Usage:  scripts/smoke/smoke.sh [path-to-networkscan-binary]
# Exit:   0 = all checks passed, 1 = one or more checks failed
#
# Note: `discover port` defaults to --scan-type SYN, which needs root. This
# script uses CONNECT throughout so it runs unprivileged. SYN mode shares the
# naabu runner setup and target parsing; only the probe differs.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${1:-}"
WORKDIR="$(mktemp -d)"
PASS=0
FAIL=0
PIDS=()

cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }

freeport() {
  python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}

# ---------------------------------------------------------------- build binary
if [[ -z "$BIN" ]]; then
  BIN="$WORKDIR/networkscan"
  say "Building networkscan"
  if ! (cd "$REPO_ROOT" && go build -mod=vendor -o "$BIN" . 2>"$WORKDIR/build.err"); then
    grep -vE 'warning:|^#' "$WORKDIR/build.err" >&2
    echo "build failed" >&2
    exit 1
  fi
fi
echo "binary: $BIN"
if ! "$BIN" version >/dev/null 2>&1; then
  echo "cannot execute $BIN -- wrong architecture, not a file, or not executable" >&2
  exit 1
fi

# --------------------------------------------------------------- test listeners
# Three listeners with distinguishable banners, plus one port left closed.
HTTP_PORT="$(freeport)"
BANNER_PORT="$(freeport)"
TLS_PORT="$(freeport)"
CLOSED_PORT="$(freeport)"   # nothing ever binds this

mkdir -p "$WORKDIR/site"
echo '<!doctype html><html><body>networkscan smoke</body></html>' >"$WORKDIR/site/index.html"
(cd "$WORKDIR/site" && python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 >"$WORKDIR/http.log" 2>&1) &
PIDS+=($!)

# A plain TCP banner server, for `discover socket` and service fingerprinting.
cat >"$WORKDIR/banner.py" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(16)
print("READY", flush=True)
def serve(c):
    try:
        c.sendall(b"220 smoke-banner-service ready\r\n")
        c.recv(1024)
    except OSError:
        pass
    finally:
        c.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY
python3 "$WORKDIR/banner.py" "$BANNER_PORT" >"$WORKDIR/banner.log" 2>&1 &
PIDS+=($!)

# A TLS listener with a self-signed cert, for `discover tls`.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$WORKDIR/key.pem" -out "$WORKDIR/cert.pem" \
  -subj "/CN=smoke.local/O=Method Security Smoke Test" \
  >"$WORKDIR/openssl.log" 2>&1
cat >"$WORKDIR/tlsserver.py" <<'PY'
import socket, ssl, sys, threading
port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(16)
print("READY", flush=True)
def serve(c):
    try:
        with ctx.wrap_socket(c, server_side=True) as s:
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
    except (OSError, ssl.SSLError):
        pass
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY
python3 "$WORKDIR/tlsserver.py" "$TLS_PORT" "$WORKDIR/cert.pem" "$WORKDIR/key.pem" \
  >"$WORKDIR/tls.log" 2>&1 &
PIDS+=($!)

say "Starting local listeners"
waitport() {
  for _ in $(seq 1 60); do
    python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.3)
sys.exit(0 if s.connect_ex(('127.0.0.1', $1)) == 0 else 1)
" && return 0
    sleep 0.25
  done
  return 1
}
for p in "$HTTP_PORT" "$BANNER_PORT" "$TLS_PORT"; do
  waitport "$p" || { echo "listener on $p failed to start" >&2; exit 1; }
done
echo "  http   127.0.0.1:$HTTP_PORT"
echo "  banner 127.0.0.1:$BANNER_PORT"
echo "  tls    127.0.0.1:$TLS_PORT"
echo "  closed 127.0.0.1:$CLOSED_PORT  (control -- must NOT be reported open)"

# ------------------------------------------------------------------- assertions
check() {
  local name="$1"; shift
  local want_exit="$1"; shift
  local out="$WORKDIR/out.json"
  "$@" >"$out" 2>"$WORKDIR/err.txt"
  local got=$?
  if [[ "$got" != "$want_exit" ]]; then
    bad "$name (exit $got, wanted $want_exit)"
    grep -v "could not initialize router" "$WORKDIR/err.txt" | sed -n '1,5p' | sed 's/^/        /'
    return
  fi
  if [[ " $* " == *" -o json "* ]]; then
    if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
      bad "$name (exit ok but output is not valid JSON)"
      head -c 200 "$out" | sed 's/^/        /'; echo
      return
    fi
  fi
  ok "$name"
}

# jsoncheck <name> <python-expr-over-d> <cmd...>
#   The predicate travels via the environment, never through shell
#   interpolation into the Python source -- predicates contain quotes.
jsoncheck() {
  local name="$1"; shift
  local expr="$1"; shift
  local out="$WORKDIR/out.json"
  "$@" >"$out" 2>"$WORKDIR/err.txt"
  local got=$?
  if [[ "$got" != 0 ]]; then
    bad "$name (exit $got)"
    grep -v "could not initialize router" "$WORKDIR/err.txt" | sed -n '1,5p' | sed 's/^/        /'
    return
  fi
  if SMOKE_EXPR="$expr" python3 -c '
import json, os, sys
d = json.load(open(sys.argv[1]))
expr = os.environ["SMOKE_EXPR"]
if not eval(expr):
    sys.exit("predicate false: " + expr)
' "$out" 2>"$WORKDIR/pred.err"; then
    ok "$name"
  else
    bad "$name ($(tail -1 "$WORKDIR/pred.err"))"
    head -c 400 "$out" | sed 's/^/        /'; echo
  fi
}

# =============================================================================
say "1. Command tree loads (forces init of nuclei, naabu, fingerprintx, docker api)"
# nuclei's runner init pulls in the docker API types and the x/crypto openpgp
# s2k registration. An init-time break from a bumped dep dies right here.
check "root help"              0 "$BIN" --help
for sub in discover enumerate pentest; do
  check "$sub help"            0 "$BIN" "$sub" --help
done
check "version"                0 "$BIN" version

say "2. Port scan via naabu -- THE locked-dependency check"
# naabu is pinned at v2.3.3 while its shared projectdiscovery graph moved with
# the nuclei bump. This proves the pinned naabu still finds real open ports and
# still rejects a closed one.
ALL_PORTS="$HTTP_PORT,$BANNER_PORT,$TLS_PORT,$CLOSED_PORT"
jsoncheck "naabu finds the open http port" \
  "$HTTP_PORT in [p['port'] for h in d['content']['result']['sockets'] for p in h['ports']]" \
  "$BIN" discover port --target 127.0.0.1 --ports "$ALL_PORTS" --scan-type CONNECT -o json
jsoncheck "naabu finds all three open ports" \
  "set(($HTTP_PORT, $BANNER_PORT, $TLS_PORT)) <= {p['port'] for h in d['content']['result']['sockets'] for p in h['ports']}" \
  "$BIN" discover port --target 127.0.0.1 --ports "$ALL_PORTS" --scan-type CONNECT -o json
jsoncheck "naabu does NOT report the closed control port" \
  "$CLOSED_PORT not in {p['port'] for h in d['content']['result']['sockets'] for p in h['ports']}" \
  "$BIN" discover port --target 127.0.0.1 --ports "$ALL_PORTS" --scan-type CONNECT -o json
jsoncheck "naabu honours an explicit single port" \
  "[p['port'] for h in d['content']['result']['sockets'] for p in h['ports']] == [$BANNER_PORT]" \
  "$BIN" discover port --target 127.0.0.1 --ports "$BANNER_PORT" --scan-type CONNECT -o json

say "3. Raw socket banner grab (gopacket-adjacent IO, net error classification)"
jsoncheck "socket reads the service banner" \
  "'smoke-banner-service' in str(d)" \
  "$BIN" discover socket --target "127.0.0.1:$BANNER_PORT" --protocol tcp -o json

say "4. TLS inspection (crypto/tls, tlsx, go-pkcs12, x509 parsing)"
jsoncheck "tls reads the certificate subject" \
  "'smoke.local' in str(d)" \
  "$BIN" discover tls --targets "127.0.0.1:$TLS_PORT" -o json

say "5. Service fingerprinting (fingerprintx plugin set)"
check "discover service"       0 "$BIN" discover service --target "127.0.0.1:$HTTP_PORT" -o json

say "6. Output writers (signal + yaml, Method-Security/pkg)"
check "output yaml"            0 "$BIN" discover port --target 127.0.0.1 --ports "$HTTP_PORT" --scan-type CONNECT -o yaml
check "output signal"          0 "$BIN" discover port --target 127.0.0.1 --ports "$HTTP_PORT" --scan-type CONNECT -o signal

say "7. Closed port and unreachable host handled without a panic"
for desc in "closed port:127.0.0.1:$CLOSED_PORT" "unroutable:192.0.2.1:80"; do
  host="${desc#*:}"; label="${desc%%:*}"
  ip="${host%:*}"; port="${host##*:}"
  "$BIN" discover socket --target "$ip:$port" --protocol tcp -o json \
    >"$WORKDIR/dead.json" 2>"$WORKDIR/dead.err"
  rc=$?
  # 126/127 mean the binary could not be executed at all. Without this guard the
  # check below would "pass" by finding no panic in the output of a command that
  # never ran.
  if [[ $rc -ge 126 ]]; then
    bad "$label handled without panic (binary did not execute, exit $rc)"
  elif grep -q "panic:" "$WORKDIR/dead.err" "$WORKDIR/dead.json" 2>/dev/null; then
    bad "$label handled without panic"
    grep -m3 -A3 "panic:" "$WORKDIR/dead.err" | sed 's/^/        /'
  else
    ok "$label handled without panic"
  fi
done

# =============================================================================
say "Result"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
