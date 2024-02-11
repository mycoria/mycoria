package dashboard

import (
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/mycoria/mycoria/api/dns"
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/storage"
)

func (d *Dashboard) mappingsPage(w http.ResponseWriter, r *http.Request) {
	// Get mappings.
	mappings, err := d.instance.Storage().QueryMappings("")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get mappings: %s", err), http.StatusInternalServerError)
		return
	}

	// Create request token.
	rToken, err := d.CreateRequestToken(
		"manage domain mapping",
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create request token: %s", err), http.StatusInternalServerError)
		return
	}

	d.render(w, r, "mappings", struct {
		*RequestToken
		Mappings []storage.StoredMapping
	}{
		RequestToken: rToken,
		Mappings:     mappings,
	})
}

func (d *Dashboard) mappingsManage(w http.ResponseWriter, r *http.Request) {
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
		"manage domain mapping",
	) {
		http.Error(w, "Token mismatch.", http.StatusBadRequest)
		return
	}

	// Get domain.
	domain := r.Form.Get("domain")
	if domain == "" {
		http.Error(w, "Domain missing.", http.StatusBadRequest)
		return
	}

	// Execute manage action
	switch r.Form.Get("action") {
	case "delete":
		err := d.instance.Storage().DeleteMapping(domain)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to delete %s: %s", domain, err), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Unknown action.", http.StatusBadRequest)
		return
	}

	d.mappingsPage(w, r)
}

var mycoDomainRegex = regexp.MustCompile(
	`^` + // match beginning
		`(` + // start subdomain group
		`(xn--)?` + // idn prefix
		`[a-z0-9_-]{1,63}` + // main chunk
		`\.` + // ending with a dot
		`)+` + // end subdomain group, allow any number of subdomains
		config.DefaultTLD + // TLD
		`$`, // match end
)

type openMappingData struct {
	*RequestToken

	MapDomain    string
	MapRouter    string
	MappedRouter string

	StatusCode int
	Error      string
	Warning    string
}

func (d *Dashboard) mappingManualOpen(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r,
		fmt.Sprintf("/open/%s.myco/%s/", r.URL.Query().Get("domain"), r.URL.Query().Get("router")),
		http.StatusTemporaryRedirect,
	)
}

func (d *Dashboard) mappingOpenPage(w http.ResponseWriter, r *http.Request) {
	// Read path values.
	data := openMappingData{
		MapDomain: r.PathValue("domain"),
		MapRouter: r.PathValue("router"),
	}

	// Check input.
	if !mycoDomainRegex.MatchString(data.MapDomain) {
		data.StatusCode = http.StatusBadRequest
		data.Error = "Invalid domain. Must end with .myco"
		d.render(w, r, "mapping-open", data)
		return
	}
	routerIP, err := netip.ParseAddr(data.MapRouter)
	if err != nil || !m.RoutingAddressPrefix.Contains(routerIP) {
		data.StatusCode = http.StatusBadRequest
		data.Error = "Invalid Mycoria router address."
		d.render(w, r, "mapping-open", data)
		return
	}

	// Check if domain is used somewhere else already.
	mycoName, cut := strings.CutSuffix(data.MapDomain, "."+config.DefaultTLD)
	if !cut {
		data.StatusCode = http.StatusBadRequest
		data.Error = "Invalid domain. Must end with .myco"
		d.render(w, r, "mapping-open", data)
		return
	}
	mappedRouter, lookupSource := d.instance.DNS().Lookup(mycoName)

	// Check source.
	switch lookupSource {
	case dns.SourceNone:
		// Continue without previously mapped router.
	case dns.SourceInternal:
		data.Error = "Domain is reserved for internal use."
		d.render(w, r, "mapping-open", data)
		return
	case dns.SourceResolveConfig:
		data.Error = "Domain is already used by resolve configuration."
		d.render(w, r, "mapping-open", data)
		return
	case dns.SourceFriend:
		data.Error = "Domain is already used by configured friend."
		d.render(w, r, "mapping-open", data)
		return
	case dns.SourceMapping:
		if routerIP == mappedRouter {
			d.mappingOpenRedirect(w, r)
			return
		}
		// Set already mapped router.
		data.MappedRouter = mappedRouter.String()
	}

	// Create request token.
	rToken, err := d.CreateRequestToken(
		"create domain mapping",
		data.MapDomain,
		data.MapRouter,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create request token: %s", err), http.StatusInternalServerError)
		return
	}
	data.RequestToken = rToken
	d.render(w, r, "mapping-open", data)
}

func (d *Dashboard) mappingOpenSet(w http.ResponseWriter, r *http.Request) {
	// Parse from data.
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form data: %s.", err), http.StatusInternalServerError)
		return
	}
	nonce := r.Form.Get("nonce")
	token := r.Form.Get("token")

	// Check if request token matches.
	domain := r.PathValue("domain")
	router := r.PathValue("router")
	if !d.CheckRequestToken(
		nonce,
		token,
		"create domain mapping",
		domain,
		router,
	) {
		http.Error(w, "Token mismatch.", http.StatusBadRequest)
		return
	}

	// Check domain.
	if !strings.HasSuffix(domain, "."+config.DefaultTLD) {
		http.Error(w, "Invalid domain.", http.StatusBadRequest)
		return
	}

	// Parse router IP.
	routerIP, err := netip.ParseAddr(router)
	if err != nil || !m.RoutingAddressPrefix.Contains(routerIP) {
		http.Error(w, "Invalid router IP.", http.StatusBadRequest)
		return
	}

	// Save new mapping.
	err = d.instance.Storage().SaveMapping(domain, routerIP)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save domain mapping: %s", err), http.StatusBadRequest)
		return
	}

	// Redirect.
	d.mappingOpenRedirect(w, r)
}

func (d *Dashboard) mappingOpenRedirect(w http.ResponseWriter, r *http.Request) {
	var url string

	// TODO: Improve this.
	parts := strings.SplitN(r.URL.Path, "/", 5)
	switch len(parts) {
	case 4:
		url = "http://" + parts[2] + "/"
	case 5:
		url = "http://" + parts[2] + "/" + parts[4]
	default:
		http.Error(w, "Invalid URL.", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
