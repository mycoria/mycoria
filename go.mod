module github.com/mycoria/mycoria

go 1.26.3

// gVisor uses special tags for go mod compatibility.
// Tags are here: https://github.com/google/gvisor/tags
// Option 1:
// - go get gvisor.dev/gvisor@go
// Option 2:
// - require gvisor.dev/gvisor go
// - go mod tidy # transforms the require into a valid version string
// Option 3: Forced, but might break IDE
// - replace gvisor.dev/gvisor => gvisor.dev/gvisor go
require gvisor.dev/gvisor v0.0.0-20260709014902-8ed0c00a3f90

require (
	github.com/brianvoe/gofakeit v3.18.0+incompatible
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/leekchan/gtf v0.0.0-20190214083521-5fba33c5b00b
	github.com/lmittmann/tint v1.1.3
	github.com/mattn/go-colorable v0.1.15
	github.com/mattn/go-isatty v0.0.22
	github.com/mdlayher/ndp v1.1.0
	github.com/miekg/dns v1.1.72
	github.com/mitchellh/copystructure v1.2.0
	github.com/mycoria/crop v0.3.1
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.11.1
	github.com/tevino/abool v1.2.0
	github.com/vishvananda/netlink v1.3.1
	github.com/zeebo/blake3 v0.2.4
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.54.0
	golang.org/x/exp v0.0.0-20260709172345-9ea1abe57597
	golang.org/x/net v0.57.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	golang.zx2c4.com/wireguard/windows v1.0.1
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
