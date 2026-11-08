// Отправитель вебхука.
//
// Собирает событие, подписывает его и отправляет получателю.
// После отправки печатает готовую curl-команду, чтобы запрос можно было
// повторить (replay) или изменить вручную для экспериментов.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type Event struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Username string `json:"username"`
}

func main() {
	target := flag.String("target", "fixed", "кому отправлять: vulnerable или fixed")
	eventType := flag.String("type", "user.registered", "тип события")
	username := flag.String("user", "alice", "имя пользователя в событии")
	age := flag.Duration("age", 0, "насколько «состарить» timestamp, например 10m")
	flag.Parse()

	secret := os.Getenv("WEBHOOK_SECRET")
	if len(secret) < 32 {
		log.Fatal("WEBHOOK_SECRET не задан или короче 32 символов (сгенерируй: openssl rand -hex 32)")
	}

	// Тело запроса. Эти байты и подписываются, и отправляются: ровно одни и те же.
	body, err := json.Marshal(Event{ID: newEventID(), Type: *eventType, Username: *username})
	if err != nil {
		log.Fatal(err)
	}

	ts := strconv.FormatInt(time.Now().Add(-*age).Unix(), 10)

	var url, signature string
	switch *target {
	case "vulnerable":
		url = "http://localhost:9001/webhook"
		// Схема уязвимого получателя: sha256(secret + body), без timestamp
		sum := sha256.Sum256(append([]byte(secret), body...))
		signature = "sha256=" + hex.EncodeToString(sum[:])
	case "fixed":
		url = "http://localhost:9002/webhook"
		// Правильная схема: HMAC-SHA256(secret, timestamp + "." + body)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	default:
		log.Fatal("-target должен быть vulnerable или fixed")
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", signature)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("не удалось отправить: ", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	fmt.Printf("Отправлено: %s\n", body)
	fmt.Printf("Ответ: %d %s\n", resp.StatusCode, bytes.TrimSpace(respBody))

	fmt.Println("\nПовторить этот же запрос (replay):")
	fmt.Printf("curl -i -X POST %s \\\n  -H 'Content-Type: application/json' \\\n  -H 'X-Timestamp: %s' \\\n  -H 'X-Signature: %s' \\\n  --data-binary '%s'\n",
		url, ts, signature, body)
}

// Случайный ID события: evt_ + 16 hex-символов
func newEventID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return "evt_" + hex.EncodeToString(b)
}
