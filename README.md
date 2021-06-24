[![Go](https://github.com/mikemackintosh/go-spf/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/mikemackintosh/go-spf/actions/workflows/go.yml) [![ReportCard](https://goreportcard.com/badge/github.com/mikemackintosh/go-spf)](https://goreportcard.com/badge/github.com/mikemackintosh/go-spf)

go-spf
======

# Objective
Provide a library that allows a developer to validate an SPF record.

# Usage
### Building
`make` will build the binary and output a local-arch compatible binary to `./bin/`.

### Library

```go
package main

import "github.com/mikemackintosh/go-spf"

func main() {
  req, err := spf.Get("mikemackintosh.com")
  if err != nil {
    fmt.Printf("error: %s\n", err)
    os.Exit(1)
  }

  result, ok := req.Validate("10.1.1.1")
  if err != nil {
    fmt.Printf("error: %s\n", err)
    os.Exit(1)
  }

  // result will return a string of:
  // #=> pass, softfail, neutral, fail

  // ok will return a boolean if the provided IP is permitted or not:
  // #=> true, false
}
```

# TODO's:
- Add support for `<type>/<prefix>`, `<type>:domain` and `<type>:domain/<prefix>`
