package dashboard

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/mycoria/mycoria/api/dns"
	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/storage"
	"golang.org/x/net/idna"
)

func (d *Dashboard) mappingsPage(w http.ResponseWriter, r *http.Request) {
	// Get mappings.
	mappings, err := d.instance.Storage().QueryMappings("")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get mappings: %s", err), http.StatusInternalServerError)
		return
	}

	// Convert mappings to IDN domain names.
	for i, mapping := range mappings {
		if strings.Contains(mapping.Domain, "xn--") {
			idnDomain, err := idna.ToUnicode(mapping.Domain)
			if err == nil {
				mapping.Domain = idnDomain
				mappings[i] = mapping
			}
		}
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
	punyDomain, err := idna.ToASCII(domain)
	if err == nil {
		domain = punyDomain
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

type openMappingData struct {
	*RequestToken

	MapDomain        string
	MapDomainCleaned string
	MapRouter        string
	MappedRouter     string

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

	// Check domain.
	if !strings.HasSuffix(data.MapDomain, config.DefaultDotTLD) {
		data.StatusCode = http.StatusBadRequest
		data.Error = "Invalid domain. Must end with .myco"
		d.render(w, r, "mapping-open", data)
		return
	}
	cleanedDomain, ok := config.CleanDomain(data.MapDomain)
	if !ok {
		data.StatusCode = http.StatusBadRequest
		data.Error = "Invalid domain."
		d.render(w, r, "mapping-open", data)
		return
	}
	data.MapDomainCleaned = cleanedDomain

	// Check router IP.
	routerIP, err := netip.ParseAddr(data.MapRouter)
	if err != nil || !m.RoutingAddressPrefix.Contains(routerIP) {
		data.StatusCode = http.StatusBadRequest
		data.Error = "Invalid Mycoria router address."
		d.render(w, r, "mapping-open", data)
		return
	}

	// Check if domain is used somewhere else already.
	// Check source.
	mappedRouter, lookupSource := d.instance.DNS().Lookup(data.MapDomainCleaned)
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
		data.MapDomainCleaned,
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

	// Check domain again.
	domain := r.PathValue("domain")
	cleanedDomain, ok := config.CleanDomain(domain)
	if !ok {
		http.Error(w, "Invalid domain.", http.StatusBadRequest)
		return
	}

	// Check if request token matches.
	router := r.PathValue("router")
	if !d.CheckRequestToken(
		nonce,
		token,
		"create domain mapping",
		cleanedDomain,
		router,
	) {
		http.Error(w, "Token mismatch.", http.StatusBadRequest)
		return
	}

	// Parse router IP.
	routerIP, err := netip.ParseAddr(router)
	if err != nil || !m.RoutingAddressPrefix.Contains(routerIP) {
		http.Error(w, "Invalid router IP.", http.StatusBadRequest)
		return
	}

	// Save new mapping.
	err = d.instance.Storage().SaveMapping(cleanedDomain, routerIP)
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
