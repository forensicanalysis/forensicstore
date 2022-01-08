<h1 align="center">forensicstore</h1>

<p  align="center">
  <a href="https://godocs.io/github.com/forensicanalysis/forensicstore"><img src="https://godocs.io/github.com/forensicanalysis/forensicstore?status.svg" alt="doc" /></a>
</p>

The forensicstore project can create, access and process forensic artifacts 
bundled in so called forensicstores (a database for forensic artifacts).

### Example

```go
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
