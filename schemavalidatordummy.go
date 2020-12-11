// +build !go1.13

package forensicstore

import (
	"github.com/tidwall/gjson"
)

func setupSchemaValidation() {}

func validateSchema(element []byte) (flaws []string, err error) {
	elementType := gjson.GetBytes(element, discriminator)
	if !elementType.Exists() {
		flaws = append(flaws, "element needs to have a type")
	}
	return flaws, nil
}
