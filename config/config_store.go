package config

import (
	"github.com/mitchellh/copystructure"

	"github.com/mycoria/mycoria/m"
)

// Store holds all configuration in a storable format.
type Store struct {
	Router Router `json:"router,omitempty" yaml:"router,omitempty"`
	System System `json:"system,omitempty" yaml:"system,omitempty"`

	ServiceConfigs []ServiceConfig   `json:"services,omitempty" yaml:"services,omitempty"`
	FriendConfigs  []FriendConfig    `json:"friends,omitempty"  yaml:"friends,omitempty"`
	ResolveConfig  map[string]string `json:"resolve,omitempty"  yaml:"resolve,omitempty"`
}

// Router defines all configuration regarding the overlay network itself.
type Router struct { //nolint:maligned
	// Address it the identity of the router.
	Address m.AddressStorage `json:"address,omitempty" yaml:"address,omitempty"`

	// Universe holds the "universe" the router is in.
	Universe       string `json:"universe,omitempty"       yaml:"universe,omitempty"`
	UniverseSecret string `json:"universeSecret,omitempty" yaml:"universeSecret,omitempty"`

	// Isolate constrains outgoing traffic to friends.
	Isolate bool `json:"isolate,omitempty" yaml:"isolate,omitempty"`

	// Listen holds the peering URLs to listen on.
	// URLs must have an IP address as host.
	Listen []string `json:"listen,omitempty" yaml:"listen,omitempty"`

	// IANA holds a list of domains or IPs assigne by IANA through which the router can be reached.
	IANA []string `json:"iana,omitempty" yaml:"iana,omitempty"`

	// Connect holds the peering URLs the router
	// tries to always hold a connection to.
	Connect []string `json:"connect,omitempty" yaml:"connect,omitempty"`

	// AutoConnect specifies whether the router should automatically peer with
	// other routers (based on live usage data) to improve network flow.
	AutoConnect bool `json:"autoConnect,omitempty" yaml:"autoConnect,omitempty"`

	// MinAutoConnect specifies the minimum amount of connections that the router
	// should automatically connect to in order to improve network flow.
	// Enables AutoConnect if defined.
	// Minimum is 1, Defaults to 2.
	MinAutoConnect int `json:"minAutoConnect,omitempty" yaml:"minAutoConnect,omitempty"`

	// Bootstrap holds peering URLs that the router uses to bootstrap to the network.
	Bootstrap []string `json:"bootstrap,omitempty" yaml:"bootstrap,omitempty"`

	// Stub runs the router in stub mode. It will not relay router announcements
	// and will appear as a dead end to other routers.
	// Forces the router to announce itself as a stub router.
	// Hint: Routers with only one peer or only lite mode peers automatically
	// announce themselves as stub routers.
	Stub bool `json:"stub,omitempty" yaml:"stub,omitempty"`

	// Lite runs the router in lite mode. It will attempt to reduce any
	// non-essential activity and traffic.
	// Behavior will slightly change over time and also depends on other routers
	// playing along - do not use for workarounds.
	Lite bool `json:"lite,omitempty" yaml:"lite,omitempty"`
}

// FriendConfig is a trusted router in the network.
type FriendConfig struct {
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	IP   string `json:"ip,omitempty"   yaml:"ip,omitempty"`
}

// ServiceConfig defines an endpoint other routers can send traffic to.
type ServiceConfig struct { //nolint:maligned
	Name        string `json:"name,omitempty"        yaml:"name,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Domain      string `json:"domain,omitempty"      yaml:"domain,omitempty"`
	URL         string `json:"url,omitempty"         yaml:"url,omitempty"`

	// Access Control
	Public  bool     `json:"public,omitempty"  yaml:"public,omitempty"`
	Friends bool     `json:"friends,omitempty" yaml:"friends,omitempty"`
	For     []string `json:"for,omitempty"     yaml:"for,omitempty"`

	Advertise bool `json:"advertise,omitempty" yaml:"advertise,omitempty"`
}

// System defines all configuration regarding the system.
type System struct { //nolint:maligned
	TunName    string `json:"tunName,omitempty"    yaml:"tunName,omitempty"`
	TunMTU     int    `json:"tunMTU,omitempty"     yaml:"tunMTU,omitempty"`
	DisableTun bool   `json:"disableTun,omitempty" yaml:"disableTun,omitempty"`

	APIListen string `json:"apiListen,omitempty" yaml:"apiListen,omitempty"`
	StatePath string `json:"statePath,omitempty" yaml:"statePath,omitempty"`

	DisableChromiumWorkaround bool `json:"disableChromiumWorkaround,omitempty" yaml:"disableChromiumWorkaround,omitempty"`
}

// Clone returns a full copy the store.
func (s Store) Clone() (Store, error) {
	copied, err := copystructure.Copy(s)
	if err != nil {
		return Store{}, err
	}
	return copied.(Store), nil //nolint:forcetypeassert
}
