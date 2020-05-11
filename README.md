<h1 align="center">forensicstore</h1>

<p  align="center">
 <a href="https://github.com/forensicanalysis/forensicstore/actions"><img src="https://github.com/forensicanalysis/forensicstore/workflows/CI/badge.svg" alt="build" /></a>
 <a href="https://codecov.io/gh/forensicanalysis/forensicstore"><img src="https://codecov.io/gh/forensicanalysis/forensicstore/branch/master/graph/badge.svg" alt="coverage" /></a>
 <a href="https://goreportcard.com/report/github.com/forensicanalysis/forensicstore"><img src="https://goreportcard.com/badge/github.com/forensicanalysis/forensicstore" alt="report" /></a>
 <a href="https://pkg.go.dev/github.com/forensicanalysis/forensicstore"><img src="https://img.shields.io/badge/go.dev-documentation-007d9c?logo=go&logoColor=white" alt="doc" /></a>
 <a href="https://app.fossa.io/projects/git%2Bgithub.com%2Fforensicanalysis%2Fforensicstore?ref=badge_shield" alt="FOSSA Status"><img src="https://app.fossa.io/api/projects/git%2Bgithub.com%2Fforensicanalysis%2Fforensicstore.svg?type=shield"/></a>
</p>

The forensicstore project can create,
access and process forensic artifacts bundled in so called forensicstores
(a database for forensic artifacts).




### Installation


```bash
go get -u github.com/forensicanalysis/forensicstore
```


### Example Code



```go
package main

import (
	"fmt"
	"github.com/forensicanalysis/forensicstore"
)

func main() {
	// create forensicstore
	store, teardown, _ := forensicstore.New("example.forensicstore")
	defer teardown()

	// create a struct
	evidence := struct {
		Data string
		Type string
	}{Data: "secret", Type: "test"}

	// insert struct into forensicstore
	store.InsertStruct(evidence)

	// get element from forensicstore
	elements, _ := store.Search("secret")

	// access element's data
	fmt.Println(elements)
}

```


## Contact

For feedback, questions and discussions you can use the [Open Source DFIR Slack](https://github.com/open-source-dfir/slack).

## Acknowledgment

The development of this software was partially sponsored by Siemens CERT, but
is not an official Siemens product.
