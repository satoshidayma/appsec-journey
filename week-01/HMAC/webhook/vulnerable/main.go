// ⚠️ УЯЗВИМЫЙ получатель вебхуков. Только для обучения.
//
// Ошибки помечены в коде как ❌ 1–4:
//  1. sha256(secret + body) вместо HMAC  → атака удлинением сообщения
//  2. подпись сравнивается через ==       → timing-атака
//  3. подпись проверяется по пересобранному JSON, а не по сырому телу
//  4. нет timestamp и ID события          → replay (повтор старого запроса)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
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
	log.Println("⚠️ УЯЗВИМЫЙ получатель: http://localhost:9001/webhook")
	log.Fatal(http.ListenAndServe(":9001", nil))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// (заодно нет ограничения размера тела: можно прислать гигабайт)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// ❌ 3. Сначала разбираем JSON в структуру...
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	// ...и подпись проверяем по ЗАНОВО собранному JSON.
	// Разные байты (лишние поля, пробелы, ключи в другом регистре)
	// превращаются в одну и ту же структуру и дают ту же подпись.
	canonical, _ := json.Marshal(event)

	// ❌ 1. Самодельная подпись: sha256(secret + body) вместо HMAC
	sum := sha256.Sum256(append(append([]byte{}, secret...), canonical...))
	expected := "sha256=" + hex.EncodeToString(sum[:])

	// ❌ 2. Обычное сравнение строк: выходит на первом несовпавшем символе
	if r.Header.Get("X-Signature") != expected {
		log.Println("отклонён: неверная подпись")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// ❌ 4. Ни timestamp, ни ID события не проверяются:
	// перехваченный запрос можно отправлять снова и снова

	process(event, raw)
	w.Write([]byte("ok\n"))
}

// "Бизнес-логика". Сырое тело сохраняется в журнал / передаётся дальше,
// хотя подпись проверялась не по нему.
func process(event Event, raw []byte) {
	log.Printf("✅ принято событие %s: %s, пользователь %q", event.ID, event.Type, event.Username)
	log.Printf("   в журнал записано сырое тело: %s", raw)
}
