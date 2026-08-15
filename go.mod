module github.com/Vidimuslabs/xap-go

go 1.26.6

// Local development and CI check xap-spec out as a sibling. Consumers ignore
// this line — replace directives apply only to the main module — so the require
// below must name a version that genuinely resolves from the proxy. Drop this
// replace when xap-spec goes public.
replace github.com/Vidimuslabs/xap-spec => ../xap-spec

require (
	github.com/Vidimuslabs/xap-spec v0.2.0-rc.1
	github.com/cloudflare/circl v1.6.4
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/veraison/go-cose v1.3.0
)

require (
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.44.0 // indirect
)
