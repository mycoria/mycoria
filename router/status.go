package router

import (
	"net/http"
	"net/netip"
	"text/template"
)

func (r *Router) registerAPI() {
	// TODO: use /{$} in Go1.22 to only match root path.
	r.instance.API().HandleFunc("status.myco/", r.statusPage)
}

var statusPageTmpl = template.Must(template.New("status page").Parse(`
Router {{ .ID }}
Version {{ .Version }}

Table:
{{ .Table }}
`))

func (r *Router) statusPage(w http.ResponseWriter, _ *http.Request) {
	// TODO: Server version based on accept header.
	// Give browser html
	// Give terminal txt

	statusPageTmpl.Execute(w, struct {
		Version string
		ID      netip.Addr
		Table   string
	}{
		Version: r.instance.Version(),
		ID:      r.instance.Identity().IP,
		Table:   r.table.Format(),
	})
}
