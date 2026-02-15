package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/mcpsek/mcpsek/internal/database"
)

// API handles HTTP API requests
type API struct {
	db *database.DB
}

// New creates a new API handler
func New(db *database.DB) *API {
	return &API{db: db}
}

// Router creates the API router
func (a *API) Router() http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)

	// Routes
	r.Get("/servers", a.listServers)
	r.Get("/servers/{id}", a.getServer)
	r.Get("/servers/{id}/scans", a.getServerScans)
	r.Get("/servers/{id}/mutations", a.getServerMutations)
	r.Get("/search", a.searchServers)
	r.Get("/stats", a.getStats)
	r.Get("/recent/critical", a.getRecentCritical)
	r.Get("/recent/mutations", a.getRecentMutations)

	return r
}

// Response wraps API responses
type Response struct {
	Data  interface{} `json:"data,omitempty"`
	Meta  *Meta       `json:"meta,omitempty"`
	Error *ErrorMsg   `json:"error,omitempty"`
}

// Meta contains pagination metadata
type Meta struct {
	Total   int    `json:"total"`
	Page    int    `json:"page"`
	PerPage int    `json:"per_page"`
	Time    string `json:"timestamp"`
}

// ErrorMsg represents an error response
type ErrorMsg struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// listServers handles GET /servers
func (a *API) listServers(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r)

	servers, total, err := a.db.ListServers(r.Context(), perPage, (page-1)*perPage)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database_error", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, Response{
		Data: servers,
		Meta: &Meta{
			Total:   total,
			Page:    page,
			PerPage: perPage,
		},
	})
}

// getServer handles GET /servers/{id}
func (a *API) getServer(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_id", "Invalid server ID")
		return
	}

	server, err := a.db.GetServer(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	// Get latest scan
	latestScan, _ := a.db.GetLatestScanForServer(r.Context(), id)

	data := map[string]interface{}{
		"server":      server,
		"latest_scan": latestScan,
	}

	respondJSON(w, http.StatusOK, Response{Data: data})
}

// getServerScans handles GET /servers/{id}/scans
func (a *API) getServerScans(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_id", "Invalid server ID")
		return
	}

	page, perPage := parsePagination(r)

	scans, total, err := a.db.GetScanHistory(r.Context(), id, perPage, (page-1)*perPage)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database_error", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, Response{
		Data: scans,
		Meta: &Meta{
			Total:   total,
			Page:    page,
			PerPage: perPage,
		},
	})
}

// getServerMutations handles GET /servers/{id}/mutations
func (a *API) getServerMutations(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_id", "Invalid server ID")
		return
	}

	page, perPage := parsePagination(r)

	mutations, total, err := a.db.GetMutationsForServer(r.Context(), id, perPage, (page-1)*perPage)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database_error", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, Response{
		Data: mutations,
		Meta: &Meta{
			Total:   total,
			Page:    page,
			PerPage: perPage,
		},
	})
}

// searchServers handles GET /search?q=query
func (a *API) searchServers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		respondError(w, http.StatusBadRequest, "missing_query", "Query parameter 'q' is required")
		return
	}

	page, perPage := parsePagination(r)

	servers, total, err := a.db.SearchServers(r.Context(), query, perPage, (page-1)*perPage)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database_error", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, Response{
		Data: servers,
		Meta: &Meta{
			Total:   total,
			Page:    page,
			PerPage: perPage,
		},
	})
}

// getStats handles GET /stats
func (a *API) getStats(w http.ResponseWriter, r *http.Request) {
	stats, err := a.db.GetStats(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database_error", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, Response{Data: stats})
}

// getRecentCritical handles GET /recent/critical
func (a *API) getRecentCritical(w http.ResponseWriter, r *http.Request) {
	scans, err := a.db.GetRecentCriticalScans(r.Context(), 10)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database_error", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, Response{Data: scans})
}

// getRecentMutations handles GET /recent/mutations
func (a *API) getRecentMutations(w http.ResponseWriter, r *http.Request) {
	mutations, err := a.db.GetRecentMutations(r.Context(), 10)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "database_error", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, Response{Data: mutations})
}

// parsePagination extracts pagination parameters from request
func parsePagination(r *http.Request) (page, perPage int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	perPage, _ = strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	return
}

// respondJSON sends a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// respondError sends an error response
func respondError(w http.ResponseWriter, status int, code, message string) {
	respondJSON(w, status, Response{
		Error: &ErrorMsg{
			Code:    code,
			Message: message,
		},
	})
}

// corsMiddleware adds CORS headers
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
