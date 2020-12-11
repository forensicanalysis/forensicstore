package forensicstore

type Validator interface {
	Setup()
	Validate(element []byte) (flaws []string, err error)
}
