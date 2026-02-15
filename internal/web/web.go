package web

import (
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/mcpsek/mcpsek/internal/database"
)

// Web handles web UI requests
type Web struct {
	db        *database.DB
	templates *template.Template
}

// New creates a new web handler
func New(db *database.DB, templatesDir string) (*Web, error) {
	tmpl, err := template.ParseGlob(filepath.Join(templatesDir, "*.html"))
	if err != nil {
		return nil, err
	}

	return &Web{
		db:        db,
		templates: tmpl,
	}, nil
}

// Router creates the web router
func (w *Web) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/", w.home)
	r.Get("/server/{id}", w.serverDetail)
	r.Get("/search", w.search)

	return r
}

// home renders the homepage
func (w *Web) home(wr http.ResponseWriter, r *http.Request) {
	stats, _ := w.db.GetStats(r.Context())
	criticalScans, _ := w.db.GetRecentCriticalScans(r.Context(), 10)
	recentMutations, _ := w.db.GetRecentMutations(r.Context(), 10)

	data := map[string]interface{}{
		"Stats":            stats,
		"CriticalScans":    criticalScans,
		"RecentMutations":  recentMutations,
	}

	w.templates.ExecuteTemplate(wr, "home.html", data)
}

// serverDetail renders a server detail page
func (w *Web) serverDetail(wr http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(wr, "Invalid server ID", http.StatusBadRequest)
		return
	}

	server, err := w.db.GetServer(r.Context(), id)
	if err != nil {
		http.Error(wr, "Server not found", http.StatusNotFound)
		return
	}

	latestScan, _ := w.db.GetLatestScanForServer(r.Context(), id)
	scans, _, _ := w.db.GetScanHistory(r.Context(), id, 10, 0)
	mutations, _, _ := w.db.GetMutationsForServer(r.Context(), id, 10, 0)
	tools, _ := w.db.GetToolDefinitionsForServer(r.Context(), id)

	data := map[string]interface{}{
		"Server":      server,
		"LatestScan":  latestScan,
		"Scans":       scans,
		"Mutations":   mutations,
		"Tools":       tools,
	}

	w.templates.ExecuteTemplate(wr, "server.html", data)
}

// search renders search results
func (w *Web) search(wr http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Redirect(wr, r, "/", http.StatusSeeOther)
		return
	}

	servers, total, _ := w.db.SearchServers(r.Context(), query, 50, 0)

	data := map[string]interface{}{
		"Query":   query,
		"Servers": servers,
		"Total":   total,
	}

	w.templates.ExecuteTemplate(wr, "search.html", data)
}
