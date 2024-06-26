package dashboard

import (
	"fmt"
	"net/http"
	"net/netip"
	"runtime"
	"runtime/debug"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/peering"
	"github.com/mycoria/mycoria/router"
	"github.com/mycoria/mycoria/storage"
)

func (d *Dashboard) registerViews() {
	api := d.instance.API()

	api.HandleFunc("GET /{$}", d.overviewPage)
	api.HandleFunc("GET /overview", d.overviewPage)
	api.HandleFunc("POST /{$}", d.overviewManage)
	api.HandleFunc("POST /overview", d.overviewManage)

	api.HandleFunc("GET /discover", d.discoverPage)
	api.HandleFunc("GET /table", d.tablePage)
	api.HandleFunc("GET /info", d.infoPage)

	api.HandleFunc("GET /mappings", d.mappingsPage)
	api.HandleFunc("POST /mappings", d.mappingsManage)

	api.HandleFunc("GET /open", d.mappingManualOpen)
	api.HandleFunc("GET /open/{domain}/{router}/", d.mappingOpenPage)
	api.HandleFunc("POST /open/{domain}/{router}/", d.mappingOpenSet)
}

func (d *Dashboard) overviewPage(w http.ResponseWriter, r *http.Request) {
	// Create request token.
	rToken, err := d.CreateRequestToken(
		"manage overview",
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create request token: %s", err), http.StatusInternalServerError)
		return
	}

	// Get runtime stats.
	memStats := new(runtime.MemStats)
	runtime.ReadMemStats(memStats)

	d.render(w, r, "overview", struct {
		*RequestToken
		NumCPU       int
		NumGoroutine int
		MemStats     *runtime.MemStats
		Peerings     []peering.Link
		Connections  []router.ExportedConnection
	}{
		RequestToken: rToken,
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		MemStats:     memStats,
		Peerings:     d.instance.Peering().GetLinks(),
		Connections:  d.instance.Router().ExportConnections(3 * time.Minute),
	})
}

func (d *Dashboard) overviewManage(w http.ResponseWriter, r *http.Request) {
	// Parse from data.
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form data: %s.", err), http.StatusInternalServerError)
		return
	}
	nonce := r.Form.Get("nonce")
	token := r.Form.Get("token")

	// Check if request token matches.
	if !d.CheckRequestToken(
		nonce,
		token,
		"manage overview",
	) {
		http.Error(w, "Token mismatch.", http.StatusBadRequest)
		return
	}

	// Execute manage action
	switch r.Form.Get("action") {
	case "close-link":
		peer, err := netip.ParseAddr(r.Form.Get("peer"))
		if err != nil {
			http.Error(w, "Invalid peer.", http.StatusBadRequest)
			return
		}
		d.instance.Peering().CloseLink(peer)

	default:
		http.Error(w, "Unknown action.", http.StatusBadRequest)
		return
	}

	d.overviewPage(w, r)
}

func (d *Dashboard) discoverPage(w http.ResponseWriter, r *http.Request) {
	ip := d.instance.Identity().IP
	newerThan := time.Now().Add(-10 * time.Minute)

	q := storage.NewRouterQuery(
		func(a *storage.StoredRouter) bool {
			return a.PublicInfo != nil &&
				len(a.PublicInfo.PublicServices) > 0 &&
				a.Universe == d.instance.Config().Router.Universe &&
				a.UpdatedAt.After(newerThan)
		},
		func(a, b *storage.StoredRouter) int {
			aDist := m.IPDistance(ip, a.Address.IP)
			bDist := m.IPDistance(ip, b.Address.IP)
			return aDist.Compare(bDist)
		},
		1024, // TODO: Unlimited? Paginated?
	)
	if err := d.instance.Storage().QueryRouters(q); err != nil {
		http.Error(w, fmt.Sprintf("failed to query router: %s", err), http.StatusInternalServerError)
		return
	}

	d.render(w, r, "discover", struct {
		Routers []*storage.StoredRouter
	}{
		Routers: q.Result(),
	})
}

func (d *Dashboard) tablePage(w http.ResponseWriter, r *http.Request) {
	d.render(w, r, "table", struct {
		Table string
		Stub  bool
		Lite  bool
	}{
		Table: d.instance.Router().Table().Format(),
		Stub:  d.instance.Config().Router.Stub,
		Lite:  d.instance.Config().Router.Lite,
	})
}

func (d *Dashboard) infoPage(w http.ResponseWriter, r *http.Request) {
	// Get build info.
	buildInfo, _ := debug.ReadBuildInfo()
	buildSettings := make(map[string]string)
	for _, setting := range buildInfo.Settings {
		buildSettings[setting.Key] = setting.Value
	}

	// Get runtime stats.
	memStats := new(runtime.MemStats)
	runtime.ReadMemStats(memStats)

	// Get, redact and marshal config.
	store, err := d.instance.Config().Store.Clone()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to clone config: %s", err), http.StatusInternalServerError)
		return
	}
	store.Router.Address.PrivateKey = "***"
	if store.Router.UniverseSecret != "" {
		store.Router.UniverseSecret = "***"
	}
	configStoreYaml, err := yaml.Marshal(store)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal config: %s", err), http.StatusInternalServerError)
		return
	}

	d.render(w, r, "info", struct {
		BuildInfo     *debug.BuildInfo
		BuildSettings map[string]string
		NumCPU        int
		NumGoroutine  int
		MemStats      *runtime.MemStats
		ConfigStore   string
	}{
		BuildInfo:     buildInfo,
		BuildSettings: buildSettings,
		NumCPU:        runtime.NumCPU(),
		NumGoroutine:  runtime.NumGoroutine(),
		MemStats:      memStats,
		ConfigStore:   string(configStoreYaml),
	})
}
