# Contributing

xap-go is the **verify-only** reference SDK for XAP. It holds no signing keys
and performs neither issuance nor enforcement.

## Develop

```
go test ./...
go run ./cmd/xap vectors run
gofmt -w .
```

Conformance vectors live in [xap-spec](https://github.com/Vidimuslabs/xap-spec)
and are pulled as a module. Do not add a `replace` for `xap-spec`.

## Scope

PRs that add signing, issuance, or enforcement will be declined. Those belong
in the licensed engine, not this repository.

## Security

See [`SECURITY.md`](SECURITY.md). Report vulnerabilities to
**security@vidimuslabs.com**. Do not open a public issue for a security report.

## License

Contributions are under Apache License 2.0. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).
