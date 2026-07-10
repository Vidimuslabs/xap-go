module github.com/Vidimuslabs/xap-go

go 1.26.4

replace github.com/Vidimuslabs/xap-spec => ../xap-spec

require (
	github.com/Vidimuslabs/xap-spec v0.0.0
	github.com/cloudflare/circl v1.6.4
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/veraison/go-cose v1.3.0
)

require (
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.38.0 // indirect
)
