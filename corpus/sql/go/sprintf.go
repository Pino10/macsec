package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func orders(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		rows, _ := db.Query(fmt.Sprintf("SELECT id, total FROM orders WHERE user = '%s'", user)) // MACSEC-SQLI
		defer rows.Close()
		w.WriteHeader(200)
	}
}
