package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

const (
	argonTime = 3
	argonMemory = 64 * 1024
	argonThreads = 4
	argonKeyLen = 32
	saltLen = 16
)

func generateRandomSalt() ([]byte, error){
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	return salt, err 
}

func hashPassword(password string, salt []byte) []byte {

	start := time.Now()
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		3,       // times: количество проходов
		64*1024, // memory
		4,       // threads: параллельные потоки
		32,      // длина результата в байтах
	)
	log.Printf("хеширование заняло %v", time.Since(start))
	return hash
}

func registration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, "../templates/register.html")
	case http.MethodPost:
		username := r.FormValue("username")
		password := r.FormValue("password") // plaintext

		if username == "" {
			http.Error(w, "Логин обязателен", http.StatusBadRequest)
			return
		}

		if utf8.RuneCountInString(password) < 8 {
			http.Error(w, "Пароль должен быть не меньше 8 символов", http.StatusBadRequest)
			return
		}

		randomSalt, err := generateRandomSalt()
		if err != nil {
			log.Println("ошибка генерации соли:", err)
			http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
			return 
		}

		passwordHash := hashPassword(password, randomSalt)

		_, err = db.Exec("INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
			username, hex.EncodeToString(randomSalt), hex.EncodeToString(passwordHash))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				http.Error(w, "Такой логин уже занят", http.StatusConflict)
				return
			}
			// Подробности пишем в лог, пользователю показываем общий текст
			log.Println("ошибка БД:", err)
			http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Пользователь %s зарегистрирован", username)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, "../templates/login.html")

	case http.MethodPost:
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Достаём соль и хеш этого пользователя
		var saltHex, hashHex string
		err := db.QueryRow(
			"SELECT salt, password_hash FROM users WHERE username = ?",
			username,
		).Scan(&saltHex, &hashHex)

		if errors.Is(err, sql.ErrNoRows) {
			// Пользователя нет, но всё равно тратим время на хеширование,
			// чтобы по скорости ответа нельзя было понять, существует ли логин
			hashPassword(password, make([]byte, saltLen))
			http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Println("ошибка БД:", err)
			http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
			return
		}

		salt, err1 := hex.DecodeString(saltHex)
		storedHash, err2 := hex.DecodeString(hashHex)
		if err1 != nil || err2 != nil {
			log.Println("повреждённые данные пользователя:", username)
			http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
			return
		}

		// Хешируем введённый пароль С ТОЙ ЖЕ солью и сравниваем
		computed := hashPassword(password, salt)

		if subtle.ConstantTimeCompare(computed, storedHash) != 1 {
			http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Добро пожаловать, %s!", username)

	default:
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
}
}

var db *sql.DB

func main() {
	var err error

	db, err = sql.Open("sqlite", "users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := createTable(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/register", registration)
	mux.HandleFunc("/login", login)

	log.Println("Сервер запущен")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func createTable() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			salt TEXT NOT NULL,
			password_hash TEXT NOT NULL
		)
	`)
	return err
}
