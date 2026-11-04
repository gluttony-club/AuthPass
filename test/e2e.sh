#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
proxy_pid= upstream_pid=
cleanup() { [[ -z "$proxy_pid" ]] || kill "$proxy_pid" 2>/dev/null || true; [[ -z "$upstream_pid" ]] || kill "$upstream_pid" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT
trap 'echo "FAIL: line $LINENO" >&2' ERR
pass() { echo "PASS: $*"; }
go build -o "$tmp/helper" ./cmd/authpass
go build -o "$tmp/upstream" ./test/upstream
"$tmp/upstream" -dir "$tmp" >"$tmp/upstream.log" 2>&1 & upstream_pid=$!
for _ in {1..100}; do [[ ! -f "$tmp/ports" ]] || break; sleep .1; done
read -r hp sp < <(cat "$tmp/ports"; echo)
cat > "$tmp/port.go" <<'GO'
package main
import("net";"fmt")
func main(){l,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil{panic(e)};fmt.Print(l.Addr().(*net.TCPAddr).Port);l.Close()}
GO
pp=$(go run "$tmp/port.go")
mkdir -p "$tmp/data"
cat > "$tmp/data/config.json" <<JSON
{"listen":"127.0.0.1:$pp","pac_path":"/proxy.pac","upstream_ca_file":"$tmp/upstream.crt","host_overrides":{"dev.foo.test":"127.0.0.1","feature.bar.test":"127.0.0.1","other.test":"127.0.0.1"},"rules":[{"id":"dev","name":"测试环境","host_prefix":"dev.","enabled":true},{"id":"staging","name":"预发环境","host_prefix":"staging.","enabled":true}]}
JSON
"$tmp/helper" -datadir "$tmp/data" >"$tmp/proxy.log" 2>&1 & proxy_pid=$!
base="http://127.0.0.1:$pp"
for _ in {1..100}; do if curl -fsS "$base/status" >/dev/null 2>&1; then break; fi; sleep .1; done
token=$(sed -n 's/.*settings?token=//p' "$tmp/proxy.log")
[[ ${#token} == 64 ]]
pass 'startup prints random settings token'
curl -fsS -H "X-Auth-Token: $token" "$base/api/preferences" > "$tmp/preferences"
rg -q '"launch_at_login":true' "$tmp/preferences"
curl -fsS -X PUT -H "X-Auth-Token: $token" "$base/api/preferences" --data '{"launch_at_login":false}' >/dev/null
rg -q '"launch_at_login": false' "$tmp/data/config.json"
curl -fsS -X PUT -H "X-Auth-Token: $token" "$base/api/preferences" --data '{"launch_at_login":true}' >/dev/null
pass 'launch-at-login preferences persist'
"$tmp/helper" -datadir "$tmp/data" >"$tmp/second.log" 2>&1
rg -q 'already running' "$tmp/second.log"
pass 'second instance exits successfully'

check() { local want=$1 user=$2; shift 2; local got; got=$(curl --noproxy '' -sS -o "$tmp/body" -w '%{http_code}' -x "$base" "$@"); [[ "$got" == "$want" ]]; if [[ "$want" == 200 ]]; then rg -q "user=$user" "$tmp/body"; else rg -q 'auth_received=false' "$tmp/body"; fi; }
check 401 '' --cacert "$tmp/upstream.crt" "https://dev.foo.test:$sp/"
pass 'unconfigured HTTPS tunnels with original upstream certificate'
curl -fsS "$base/proxy.pac" > "$tmp/pac"
! rg -q 'return "PROXY' "$tmp/pac"
pass 'initial PAC does not proxy unconfigured rules'
[[ $(curl -sS -o /dev/null -w '%{http_code}' "$base/api/rules") == 401 ]]
pass 'API rejects missing token'
[[ $(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: evil.test' -H "X-Auth-Token: $token" "$base/api/rules") == 403 ]]
pass 'API rejects bad Host'
[[ $(curl -sS -o /dev/null -w '%{http_code}' -H 'Origin: http://evil.test' -H "X-Auth-Token: $token" "$base/api/rules") == 403 ]]
pass 'API rejects bad Origin'
curl -fsS -X PUT -H "X-Auth-Token: $token" -H 'Content-Type: application/json' "$base/api/rules" --data '[{"id":"dev","name":"测试环境","host_prefix":"dev.","username":"test-user","password":"test-password","enabled":true},{"id":"feature","name":"功能环境","host_prefix":"feature.","username":"feature-user","password":"feature-password","enabled":true}]' > /dev/null
pass 'settings API saves per-rule credentials'
curl -fsS "$base/proxy.pac" > "$tmp/pac"
rg -q 'shExpMatch\(host, "dev\.\*"\).*PROXY' "$tmp/pac"
rg -q 'shExpMatch\(host, "feature\.\*"\).*PROXY' "$tmp/pac"
pass 'PAC hot reload includes both configured prefixes'
for entry in 'dev.foo.test test-user' 'feature.bar.test feature-user'; do
 read -r host user <<< "$entry"
 check 200 "$user" "http://$host:$hp/"
 pass "HTTP $host receives $user credentials"
 check 200 "$user" --cacert "$tmp/data/ca.crt" "https://$host:$sp/"
 pass "HTTPS $host uses local CA and $user credentials"
done
check 401 '' "http://other.test:$hp/"
check 401 '' --cacert "$tmp/upstream.crt" "https://other.test:$sp/"
pass 'non-target HTTP/HTTPS untouched with upstream certificate'
! rg -q 'test-password|feature-password|"password"' "$tmp/data/config.json"
curl -fsS -H "X-Auth-Token: $token" "$base/api/rules" > "$tmp/rules"
! rg -q 'test-password|feature-password' "$tmp/rules"
rg -q '"has_password":true' "$tmp/rules"
pass 'passwords absent from config and API responses'
kill "$proxy_pid"; wait "$proxy_pid"; proxy_pid=
"$tmp/helper" -datadir "$tmp/data" >"$tmp/proxy.log" 2>&1 & proxy_pid=$!
for _ in {1..100}; do if curl -fsS "$base/status" >/dev/null 2>&1; then break; fi; sleep .1; done
check 200 test-user --cacert "$tmp/data/ca.crt" "https://dev.foo.test:$sp/"
pass 'config and secrets survive restart'
echo PASS
