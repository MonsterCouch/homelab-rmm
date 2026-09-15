package server

import (
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/web"
)

// staticHandler serves the embedded single-page app. Unknown paths fall back
// to index.html so client-side routes deep-link correctly.
func (s *Server) staticHandler() http.Handler {
	var root fs.FS
	if s.cfg.DevWebDir != "" {
		root = os.DirFS(s.cfg.DevWebDir)
	} else {
		sub, err := fs.Sub(web.Dist, "dist")
		if err != nil {
			panic(err)
		}
		root = sub
	}
	fileServer := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := root.Open(p); err == nil {
			f.Close()
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback
		r.URL.Path = "/"
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})
}
