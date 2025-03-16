module github.com/mycoria/mycoria

go 1.23.1

toolchain go1.24.0

// gVisor uses special tags for go mod compatibility.
// Tags are here: https://github.com/google/gvisor/tags
// Option 1:
// - go get gvisor.dev/gvisor@go
// Option 2:
// - require gvisor.dev/gvisor go
// - go mod tidy # transforms the require into a valid version string
// Option 3: Forced, but might break IDE
// - replace gvisor.dev/gvisor => gvisor.dev/gvisor go
require gvisor.dev/gvisor v0.0.0-20250314001526-eeca54973f8b

require (
	github.com/brianvoe/gofakeit v3.18.0+incompatible
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/leekchan/gtf v0.0.0-20190214083521-5fba33c5b00b
	github.com/lmittmann/tint v1.0.7
	github.com/mattn/go-colorable v0.1.14
	github.com/mattn/go-isatty v0.0.20
	github.com/mdlayher/ndp v1.1.0
	github.com/miekg/dns v1.1.63
	github.com/mitchellh/copystructure v1.2.0
	github.com/spf13/cobra v1.9.1
	github.com/spf13/pflag v1.0.6
	github.com/stretchr/testify v1.8.4
	github.com/tevino/abool v1.2.0
	github.com/vishvananda/netlink v1.3.0
	github.com/zeebo/blake3 v0.2.4
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.36.0
	golang.org/x/exp v0.0.0-20250305212735-054e65f0b394
	golang.org/x/net v0.37.0
	golang.org/x/sys v0.31.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
	golang.zx2c4.com/wireguard/windows v0.5.3
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.31.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
