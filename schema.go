// Copyright (c) 2020 Siemens AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Author(s): Jonas Plum

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
