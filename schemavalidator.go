// +build go1.13

package forensicstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/qri-io/jsonschema"
	"github.com/tidwall/gjson"

	"github.com/forensicanalysis/stixgo"
)

func setupSchemaValidation() {
	// unmarshal schemas
	registry := jsonschema.GetSchemaRegistry()
	for _, content := range stixgo.FS {
		// convert to draft/2019-09
		content = bytes.Replace(content, []byte(`"definitions"`), []byte(`"$defs"`), -1)
		content = bytes.Replace(content, []byte(`"#/definitions/`), []byte(`"#/$defs/`), -1)
		content = bytes.Replace(content,
			[]byte(`"$schema": "http://json-schema.org/draft-07/schema#",`),
			[]byte(`"$schema": "https://json-schema.org/draft/2019-09/schema#",`),
			-1,
		)

		schema := &jsonschema.Schema{}
		if err := json.Unmarshal(content, schema); err != nil {
			panic(err)
		}

		id := string(*schema.JSONProp("$id").(*jsonschema.ID))
		schema.Resolve(nil, id)
		registry.Register(schema)
	}
}

func validateSchema(element JSONElement) (flaws []string, err error) {
	elementType := gjson.GetBytes(element, discriminator)
	if !elementType.Exists() {
		flaws = append(flaws, "element needs to have a type")
	}

	schema := jsonschema.GetSchemaRegistry().GetKnown(fmt.Sprintf(
		"http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/observables/%s.json",
		elementType.String(),
	))

	if schema == nil {
		return nil, nil
	}

	errs, err := schema.ValidateBytes(context.Background(), element)
	if err != nil {
		return nil, err
	}
	for _, verr := range errs {
		flaws = append(flaws, fmt.Sprintf("failed to validate element: %s", verr))
	}
	return flaws, nil
}
