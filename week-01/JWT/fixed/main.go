// ============================================================================
//  FIXED-ВЕРСИЯ: проверка JWT с жёстким списком алгоритмов,
//  проверкой exp, aud и iss.
// ============================================================================
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("secret") // в реальном проекте — длинный случайный ключ из env/секретницы

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
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(jwtSecret)
}

// ===== Проверка токена (безопасная) =====
func ParseToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (any, error) {
			return jwtSecret, nil
		},
		// ФИКС 1: жёсткий список алгоритмов — "none" и всё остальное отклоняется.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		// ФИКС 2: exp обязателен и сверяется с текущим временем
		// (сверка включена по умолчанию, пока WithoutClaimsValidation не стоит).
		jwt.WithExpirationRequired(),
		// ФИКС 3: issuer должен совпадать с ожидаемым.
		jwt.WithIssuer(tokenIssuer),
		// ФИКС 4: audience должен совпадать с ожидаемым.
		jwt.WithAudience(tokenAudience),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
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
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			http.Error(w, "token expired", http.StatusUnauthorized)
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			http.Error(w, "invalid issuer", http.StatusUnauthorized)
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			http.Error(w, "invalid audience", http.StatusUnauthorized)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			http.Error(w, "invalid signature", http.StatusUnauthorized)
		default:
			http.Error(w, "invalid token", http.StatusUnauthorized) // без деталей наружу
		}
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

	addr := "127.0.0.1:8081"
	log.Printf("FIXED server listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}