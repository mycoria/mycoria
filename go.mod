module github.com/mycoria/mycoria

go 1.21.2

// gVisor uses special tags for go mod compatibility.
// Tags are here: https://github.com/google/gvisor/tags
// Option 1:
// - go get gvisor.dev/gvisor@go
// Option 2:
// - require gvisor.dev/gvisor go
// - go mod tidy # transforms the require into a valid version string
// Option 3: Forced, but might break IDE
// - replace gvisor.dev/gvisor => gvisor.dev/gvisor go
require gvisor.dev/gvisor v0.0.0-20240131012156-7a79184a819b

require (
	github.com/brianvoe/gofakeit v3.18.0+incompatible
	github.com/fxamacker/cbor/v2 v2.5.0
	github.com/godbus/dbus/v5 v5.1.0
	github.com/lmittmann/tint v1.0.4
	github.com/mattn/go-isatty v0.0.20
	github.com/mdlayher/ndp v1.0.1
	github.com/miekg/dns v1.1.58
	github.com/spf13/cobra v1.8.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.4
	github.com/tevino/abool v1.2.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	github.com/zeebo/blake3 v0.2.3
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.18.0
	golang.org/x/exp v0.0.0-20240119083558-1b970713d09a
	golang.org/x/net v0.20.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
