package main

import (
	"database/sql"
	"net/http"
)

func orders(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		rows, _ := db.Query("SELECT id, total FROM orders WHERE user = $1", user)
		defer rows.Close()
		w.WriteHeader(200)
	}
}
