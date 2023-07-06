# cosesign1go

[![go.dev](https://pkg.go.dev/badge/github.com/microsoft/cosesign1go.svg)](https://pkg.go.dev/github.com/microsoft/cosesign1go)
[![tests](https://github.com/microsoft/cosesign1go/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/cosesign1go/actions?query=workflow%3Aci)

A Go library to handle COSE Sign1 documents

COSE_Sign1 envelopes are signed wrappers for arbitrary data. See https://datatracker.ietf.org/doc/html/rfc8152.

## Building

Usually the library is consumed by a larger application. However, we provide a small utility (`sign1util`) that exercises the library and is useful for exploring COSE_Sign1 documents.

```go build -o sign1util cmd/sign1util/main.go```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
