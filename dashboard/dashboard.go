package dashboard

import (
	"crypto/rand"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path"
	"strings"
	txtTemplate "text/template"
	"time"

	"github.com/leekchan/gtf"

	"github.com/mycoria/mycoria/api/dns"
	"github.com/mycoria/mycoria/api/httpapi"
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
	"github.com/mycoria/mycoria/router"
	"github.com/mycoria/mycoria/state"
	"github.com/mycoria/mycoria/storage"
)

var (
	//go:embed assets
	assetsFS embed.FS

	//go:embed views
	templateFS embed.FS
)

// Dashboard is a dashboard user interface.
type Dashboard struct {
	mgr      *mgr.Manager
	instance instance

	assetServer http.Handler
	assetsEtag  string

	tokenSecret []byte

	htmlTemplates map[string]*template.Template
	txtTemplates  *txtTemplate.Template
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	Storage() storage.Storage
	State() *state.State
	API() *httpapi.API
	DNS() *dns.Server
	Router() *router.Router
	Peering() *peering.Peering
}

// New adds a dashboard to the given instance.
func New(instance instance) (*Dashboard, error) {
	d := &Dashboard{
		instance:    instance,
		assetServer: http.FileServerFS(assetsFS),
		assetsEtag:  fmt.Sprintf(`"%x"`, instance.Config().Started().UnixNano()),
	}
	d.registerRoutes()

	// Generate token secret.
	d.tokenSecret = make([]byte, tokenSecretSize)
	_, err := rand.Read(d.tokenSecret)
	if err != nil {
		return nil, fmt.Errorf("generate token secret: %w", err)
	}

	// Load templates from embedded data.
	err = d.loadTemplates(templateFS)
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}

	return d, nil
}

// Manager returns the module's manager.
func (d *Dashboard) Manager() *mgr.Manager {
	return d.mgr
}

// Start starts the router.
func (d *Dashboard) Start() error {
	return nil
}

// Stop stops the router.
func (d *Dashboard) Stop() error {
	return nil
}

func (d *Dashboard) registerRoutes() {
	d.instance.API().HandleFunc("/assets/", d.serveAssets)

	d.registerViews()
}

func (d *Dashboard) serveAssets(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "public, max-age=10")
	w.Header().Add("Etag", d.assetsEtag)
	if r.Header.Get("If-None-Match") == d.assetsEtag {
		http.Error(w, "", http.StatusNotModified)
		return
	}

	d.assetServer.ServeHTTP(w, r)
}

func (d *Dashboard) loadTemplates(baseFS fs.FS) error {
	// Load html templates.
	includeTemplates, err := template.New("").Funcs(gtf.GtfFuncMap).ParseFS(baseFS, "views/include/*.html")
	if err != nil {
		return fmt.Errorf("load include templates: %w", err)
	}
	// Parse every page template together with the includes.
	views, err := fs.ReadDir(baseFS, "views")
	if err != nil {
		return fmt.Errorf("load page names: %w", err)
	}
	d.htmlTemplates = make(map[string]*template.Template)
	for _, view := range views {
		if view.IsDir() || !strings.HasSuffix(view.Name(), ".html") {
			continue
		}
		cloned, err := includeTemplates.Clone()
		if err != nil {
			return fmt.Errorf("clone include templates: %w", err)
		}
		pageTmpl, err := cloned.ParseFS(baseFS, path.Join("views", view.Name()))
		if err != nil {
			return fmt.Errorf("parse page %s template: %w", view.Name(), err)
		}
		d.htmlTemplates[view.Name()] = pageTmpl
	}

	// Load txt templates.
	d.txtTemplates, err = txtTemplate.New("").Funcs(gtf.GtfFuncMap).ParseFS(baseFS, "views/*.txt")
	if err != nil {
		return fmt.Errorf("load txt templates: %w", err)
	}

	return nil
}

type renderingData struct {
	RouterID  netip.Addr
	RouterIDA string
	RouterIDB string
	Version   string
	Hostname  string
	Started   time.Time
	Uptime    time.Duration
	Page      any
}

var (
	html  = "html"
	plain = "plain"
)

func (d *Dashboard) render(w http.ResponseWriter, r *http.Request, templateName string, data any) {
	var err error

	// Build render data set.
	hostname, _ := os.Hostname()
	id := d.instance.Identity().IP.StringExpanded()
	renderData := &renderingData{
		RouterID:  d.instance.Identity().IP,
		RouterIDA: id[:19],
		RouterIDB: id[20:],
		Version:   d.instance.Version(),
		Hostname:  hostname,
		Started:   d.instance.Config().Started(),
		Uptime:    d.instance.Config().Uptime(),
		Page:      data,
	}

	// Reload templates in dev mode.
	if d.instance.Config().DevMode() {
		// TODO: Not concurrency safe.
		err := d.loadTemplates(os.DirFS("../../dashboard"))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to load templates: %s", err), http.StatusInternalServerError)
			return
		}
	}

	// Find out which content type to use.
	contentType := html
	accept := r.Header.Get("Accept")
	userAgent := strings.ToLower(r.Header.Get("User-Agent"))
	switch {
	case strings.Contains(accept, "text/html"):
		contentType = html
	case strings.Contains(accept, "text/plain"):
		contentType = plain
	case strings.Contains(userAgent, "curl"):
		contentType = plain
	}
	w.Header().Set("Content-Type", "text/"+contentType+"; charset=utf-8")

	// Set content type and render.
	switch contentType {
	case plain:
		err = d.txtTemplates.ExecuteTemplate(w, templateName+".txt", renderData)
	case html:
		fallthrough
	default:
		templateName += ".html"
		tmpl, ok := d.htmlTemplates[templateName]
		if ok {
			err = tmpl.ExecuteTemplate(w, templateName, renderData)
		} else {
			err = fmt.Errorf("template %q not found", templateName)
		}
	}

	// Log render error.
	if err != nil {
		d.mgr.Error(
			"failed to render",
			"template", templateName,
			"err", err,
		)
	}
}
