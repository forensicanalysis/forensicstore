package forensicstore

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/qri-io/jsonschema"

	"github.com/forensicanalysis/stixgo"
)

var Schemas map[string]*jsonschema.RootSchema // nolint:gochecknoglobals

func init() { // nolint:gochecknoinits
	Schemas = make(map[string]*jsonschema.RootSchema)
	nameTitle := map[string]string{}
	// unmarshal schemas
	for name, content := range stixgo.FS {
		schema := &jsonschema.RootSchema{}
		if err := json.Unmarshal(content, schema); err != nil {
			panic(err)
		}

		nameTitle[path.Base(name)] = schema.Title

		Schemas[schema.Title] = schema
	}

	// replace refs
	for _, schema := range Schemas {
		err := walkJSON(schema, func(elem jsonschema.JSONPather) error {
			if sch, ok := elem.(*jsonschema.Schema); ok {
				if sch.Ref != "" && sch.Ref[0] != '#' {
					sch.Ref = "elementary:" + nameTitle[path.Base(sch.Ref)]
				}
			}
			return nil
		})
		if err != nil {
			panic(err)
		}

		jsonschema.DefaultSchemaPool["elementary:"+schema.Title] = &schema.Schema
	}

	// fetch references
	for _, schema := range Schemas {
		err := schema.FetchRemoteReferences()
		if err != nil {
			panic(fmt.Sprint("could not FetchRemoteReferences:", err))
		}
	}
}

func walkJSON(elem jsonschema.JSONPather, fn func(elem jsonschema.JSONPather) error) error {
	if err := fn(elem); err != nil {
		return err
	}

	if con, ok := elem.(jsonschema.JSONContainer); ok {
		for _, ch := range con.JSONChildren() {
			if err := walkJSON(ch, fn); err != nil {
				return err
			}
		}
	}

	return nil
}
