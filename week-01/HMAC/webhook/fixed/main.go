// ✅ Исправленный получатель вебхуков.
//
// Порядок проверок:
//  1. читаем СЫРОЕ тело с ограничением размера
//  2. проверяем, что timestamp свежий (не старше 5 минут)
//  3. считаем HMAC-SHA256(secret, timestamp + "." + сырое тело)
//  4. сравниваем через hmac.Equal (за постоянное время)
//  5. только теперь разбираем JSON
//  6. проверяем, что событие с таким ID ещё не обрабатывалось
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxBodySize = 1 << 20         // 1 МБ
	maxAge      = 5 * time.Minute // окно, в котором запрос считается свежим
)

type Event struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Username string `json:"username"`
}

var secret []byte

func main() {
	s := os.Getenv("WEBHOOK_SECRET")
	if len(s) < 32 {
		log.Fatal("WEBHOOK_SECRET не задан или короче 32 символов")
	}
	secret = []byte(s)

	http.HandleFunc("/webhook", webhookHandler)
	log.Println("✅ Исправленный получатель: http://localhost:9002/webhook")
	log.Fatal(http.ListenAndServe(":9002", nil))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Сырое тело, не больше maxBodySize
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// 2. Timestamp: есть, это число, и он не старше maxAge
	tsHeader := r.Header.Get("X-Timestamp")
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		reject(w, "missing or invalid timestamp")
		return
	}
	age := time.Since(time.Unix(ts, 0))
	if age > maxAge || age < -maxAge {
		reject(w, "timestamp expired")
		return
	}

	// 3. Подпись из заголовка: "sha256=<hex>"
	sigHex, ok := strings.CutPrefix(r.Header.Get("X-Signature"), "sha256=")
	if !ok {
		reject(w, "missing signature")
		return
	}
	received, err := hex.DecodeString(sigHex)
	if err != nil {
		reject(w, "invalid signature")
		return
	}

	// Сами считаем HMAC по тем же байтам, что подписал отправитель.
	// Timestamp входит в подпись, иначе его можно было бы просто подменить.
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tsHeader + "."))
	mac.Write(raw)
	expected := mac.Sum(nil)

	// 4. Сравнение за постоянное время
	if !hmac.Equal(received, expected) {
		reject(w, "invalid signature")
		return
	}

	// 5. Подпись верна, только теперь разбираем JSON
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil || event.ID == "" {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	// 6. Защита от повтора внутри окна maxAge.
	// Проверка ПОСЛЕ подписи: иначе атакующий мог бы заранее
	// "занять" чужие ID поддельными запросами.
	if !markProcessed(event.ID) {
		reject(w, "duplicate event")
		return
	}

	log.Printf("✅ принято событие %s: %s, пользователь %q", event.ID, event.Type, event.Username)
	w.Write([]byte("ok\n"))
}

func reject(w http.ResponseWriter, reason string) {
	log.Println("отклонён:", reason)
	http.Error(w, reason, http.StatusUnauthorized)
}

// ===== Хранилище обработанных ID =====
//
// В памяти, для обучения. В реальном сервисе: БД или Redis с TTL.
// ID достаточно хранить в течение maxAge: более старые запросы
// и так отсекаются проверкой timestamp.

var (
	mu        sync.Mutex
	processed = map[string]time.Time{}
)

// Возвращает true, если ID встретился впервые
func markProcessed(id string) bool {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	for k, seen := range processed {
		if now.Sub(seen) > 2*maxAge {
			delete(processed, k)
		}
	}

	if _, dup := processed[id]; dup {
		return false
	}
	processed[id] = now
	return true
}
