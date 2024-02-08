package dashboard

import (
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"

	"gopkg.in/yaml.v3"
)

func (d *Dashboard) registerViews() {
	api := d.instance.API()

	api.HandleFunc("/{$}", d.statusPage)
	api.HandleFunc("/status", d.statusPage)
	api.HandleFunc("/discover", d.discoverPage)
	api.HandleFunc("/mappings", d.mappingsPage)
	api.HandleFunc("/table", d.tablePage)
	api.HandleFunc("/config", d.configPage)
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
	d.render(w, r, "discover", nil)
}

func (d *Dashboard) mappingsPage(w http.ResponseWriter, r *http.Request) {
	d.render(w, r, "mappings", nil)
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
