package dashboard

import (
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/storage"
)

func (d *Dashboard) registerViews() {
	api := d.instance.API()

	api.HandleFunc("GET /{$}", d.statusPage)
	api.HandleFunc("GET /status", d.statusPage)
	api.HandleFunc("GET /discover", d.discoverPage)
	api.HandleFunc("GET /table", d.tablePage)
	api.HandleFunc("GET /config", d.configPage)

	api.HandleFunc("GET /mappings", d.mappingsPage)
	api.HandleFunc("POST /mappings", d.mappingsManage)

	api.HandleFunc("GET /open", d.mappingManualOpen)
	api.HandleFunc("GET /open/{domain}/{router}/", d.mappingOpenPage)
	api.HandleFunc("POST /open/{domain}/{router}/", d.mappingOpenSet)
}

func (d *Dashboard) statusPage(w http.ResponseWriter, r *http.Request) {
	// TODO: Server version based on accept header.
	// Give browser html
	// Give terminal txt

	buildInfo, _ := debug.ReadBuildInfo()
	buildSettings := make(map[string]string)
	for _, setting := range buildInfo.Settings {
		buildSettings[setting.Key] = setting.Value
	}

	memStats := new(runtime.MemStats)
	runtime.ReadMemStats(memStats)

	d.render(w, r, "status", struct {
		BuildInfo     *debug.BuildInfo
		BuildSettings map[string]string
		NumCPU        int
		NumGoroutine  int
		MemStats      *runtime.MemStats
	}{
		BuildInfo:     buildInfo,
		BuildSettings: buildSettings,
		NumCPU:        runtime.NumCPU(),
		NumGoroutine:  runtime.NumGoroutine(),
		MemStats:      memStats,
	})
}

func (d *Dashboard) discoverPage(w http.ResponseWriter, r *http.Request) {
	ip := d.instance.Identity().IP
	newerThan := time.Now().Add(-10 * time.Minute)

	q := storage.NewRouterQuery(
		func(a *storage.StoredRouter) bool {
			return a.PublicInfo != nil &&
				len(a.PublicInfo.PublicServices) > 0 &&
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
	}{
		Table: d.instance.Router().Table().Format(),
	})
}

func (d *Dashboard) configPage(w http.ResponseWriter, r *http.Request) {
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

	d.render(w, r, "config", struct {
		ConfigStore string
	}{
		ConfigStore: string(configStoreYaml),
	})
}
