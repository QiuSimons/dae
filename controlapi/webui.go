package controlapi

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
	"github.com/daeuniverse/dae/common/consts"
)

const webUIDirEnv = "DAE_WEBUI_DIR"

type webUI struct {
	dir        string
	fileServer http.Handler
}

func discoverWebUI() *webUI {
	for _, dir := range webUIDirs() {
		if dir == "" {
			continue
		}
		if isWebUIDir(dir) {
			return &webUI{
				dir:        dir,
				fileServer: http.FileServer(http.Dir(dir)),
			}
		}
	}
	return nil
}

func webUIDirs() []string {
	dirs := make([]string, 0, 8)
	seen := map[string]struct{}{}
	add := func(dir string) {
		if dir == "" {
			return
		}
		clean := filepath.Clean(dir)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		dirs = append(dirs, clean)
	}
	addWithParents := func(base string) {
		if base == "" {
			return
		}
		current := filepath.Clean(base)
		for range 4 {
			add(filepath.Join(current, "ui"))
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}

	add(os.Getenv(webUIDirEnv))

	if cwd, err := os.Getwd(); err == nil {
		addWithParents(cwd)
	}

	if exePath, err := os.Executable(); err == nil {
		addWithParents(filepath.Dir(exePath))
	}

	appDir := consts.AppName
	add(filepath.Join(xdg.DataHome, appDir, "ui"))
	for _, base := range xdg.DataDirs {
		add(filepath.Join(base, appDir, "ui"))
	}
	add(filepath.Join("/usr/local/share", appDir, "ui"))
	add(filepath.Join("/usr/share", appDir, "ui"))

	return dirs
}

func isWebUIDir(dir string) bool {
	required := []string{"index.html", "styles.css", "script.js"}
	for _, name := range required {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.IsDir() {
			return false
		}
	}
	return true
}

func isWebUIPath(path string) bool {
	return path == "/ui" || path == "/ui/" || strings.HasPrefix(path, "/ui/")
}

func (u *webUI) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if r.URL.Path == "/ui" {
		http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/ui")
	if trimmed == "" {
		trimmed = "/"
	}

	clone := r.Clone(r.Context())
	clone.URL.Path = trimmed
	u.fileServer.ServeHTTP(w, clone)
}
