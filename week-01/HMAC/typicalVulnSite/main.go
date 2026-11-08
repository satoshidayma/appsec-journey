package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"
	_ "modernc.org/sqlite"
)

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

		_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)",
			username, password)
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

		log.Printf("Приняты данные: логин=%s и пароль=%s", username, password)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Пользователь %s зарегистрирован", username)
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

	log.Println("Сервер запущен")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func createTable() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
		)
	`)
	return err
}
