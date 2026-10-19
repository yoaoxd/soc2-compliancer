package web

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

func PathValue(r *http.Request, key string) string {
	return chi.URLParam(r, key)
}
