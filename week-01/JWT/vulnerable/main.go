// ============================================================================
//  VULN-ВЕРСИЯ: проверка JWT БЕЗ проверок алгоритма, exp, aud, iss.
//  Учебный пример, не для прода.
// ============================================================================
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("secret")

const (
	tokenIssuer   = "jwtlab-auth"
	tokenAudience = "jwtlab-api"
)

type Claims struct {
	UserID int64  `json:"uid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// ===== Генерация токена =====
// Токен всё равно содержит exp/iss/aud — проблема не в выдаче, а в том,
// что валидатор их не проверяет (см. ParseToken).
func GenerateToken(uid int64, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: uid,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprint(uid),
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{tokenAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(jwtSecret)
}

// ===== Проверка токена (уязвимая) =====
func ParseToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (any, error) {
			// УЯЗВИМОСТЬ 1: нет проверки алгоритма — keyFunc отдаёт секрет
			// для любого алгоритма, который прислал клиент, включая "none".
			if t.Method == jwt.SigningMethodNone {
				return jwt.UnsafeAllowNoneSignatureType, nil
			}
			return jwtSecret, nil
		},
		// УЯЗВИМОСТЬ 2: WithValidMethods не передан — список алгоритмов не ограничен.
		// УЯЗВИМОСТЬ 3 и 4 ниже: aud/iss не проверяются никак.
		jwt.WithoutClaimsValidation(), // УЯЗВИМОСТЬ 3: отключает проверку exp/nbf.
	)
	if err != nil {
		return nil, err
	}
	// УЯЗВИМОСТЬ 4: aud/iss из токена никогда не сравниваются с ожидаемыми значениями.
	return claims, nil
}

// ===== HTTP =====

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Username != "alice" || req.Password != "alice" {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := GenerateToken(2, "user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"access_token": token})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenStr == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	claims, err := ParseToken(tokenStr)
	if err != nil {
		http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"uid":  claims.UserID,
		"role": claims.Role,
		"aud":  claims.Audience,
		"iss":  claims.Issuer,
		"exp":  claims.ExpiresAt,
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /protected", protectedHandler)

	addr := "127.0.0.1:8080"
	log.Printf("VULN server listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}