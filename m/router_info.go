package m

// RouterInfo holds information about a router.
type RouterInfo struct {
	Version string `cbor:"v,omitempty" json:"version,omitempty" yaml:"version,omitempty"`

	Listeners []string `cbor:"l,omitempty" json:"listeners,omitempty" yaml:"listeners,omitempty"`
	IANA      []string `cbor:"i,omitempty" json:"iana,omitempty"      yaml:"iana,omitempty"`

	PublicServices []RouterService `cbor:"srv,omitempty" json:"publicServices,omitempty" yaml:"publicServices,omitempty"`
}

// RouterService describes a service offered by a router.
type RouterService struct {
	Name        string `cbor:"n,omitempty"   json:"name,omitempty"        yaml:"name,omitempty"`
	Description string `cbor:"d,omitempty"   json:"description,omitempty" yaml:"description,omitempty"`
	Domain      string `cbor:"dns,omitempty" json:"domain,omitempty"      yaml:"domain,omitempty"`
	URL         string `cbor:"url,omitempty" json:"url,omitempty"         yaml:"url,omitempty"`
}
