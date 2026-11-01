package main

import (
	"fmt"
	"log"
	"net/http"
)
var allowed_list = map[string]bool {
	"http://localhost:8000": true,
}
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Vary", "Origin")

		if allowed_list[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name: "session",
			Value: "abc123123",
			HttpOnly: true,
			Secure: true,
		})
		fmt.Fprintln(w, "Cookie set. Ready to exploiting")
	})

	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			fmt.Fprintln(w, "Cookie wasnt set yet")
		}
		fmt.Fprintln(w, cookie.Value)
	})

	handler := corsMiddleware(mux)

	log.Println("listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", handler))	
}

