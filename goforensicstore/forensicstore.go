// Copyright (c) 2019 Siemens AG
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

// Package goforensicstore provides functions to handle forensicstores.
package goforensicstore

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/fatih/structs"
	"github.com/iancoleman/strcase"
	"github.com/pkg/errors"
	"github.com/qri-io/jsonschema"

	"github.com/forensicanalysis/forensicstore/gojsonlite"
	"github.com/forensicanalysis/forensicstore/gostore"
	"github.com/forensicanalysis/stixgo"
)

//go:generate resources -declare -var=FS -package assets -output assets/assets.go ../pyforensicstore/schemas/*

// The ForensicStore is a central storage for elements in digital forensic
// investigations. It stores any piece of information in the investigation and
// serves as a single source of truth for the data. Cases, artifacts, evidence,
// meta data, bookmarks etc. can be stored in the forensicstore. Larger binary
// objects like files are usually stored outside the forensicstore and references
// from the forensicstore.
type ForensicStore struct {
	gostore.Store
}

// New creates a new ForensicStore based on the passed gostore.Store.
func New(store gostore.Store) (*ForensicStore, error) {
	// TODO: add schemas
	return &ForensicStore{store}, nil
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

// NewJSONLite creates or opens a forensicstore from an JSONLite database.
func NewJSONLite(remoteURL string) (*ForensicStore, error) {
	store, err := gojsonlite.New(remoteURL)
	if err != nil {
		return nil, err
	}

	// unmarshal schemas
	for name, content := range stixgo.FS {
		schema := &jsonschema.RootSchema{}
		if err := json.Unmarshal(content, schema); err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("unmarshal error %s", name))
		}

		err = store.SetSchema(schema.Title, schema)
		if err != nil {
			return nil, err
		}
	}

	// replace refs
	for _, schema := range store.Schemas() {
		/*
			fmt.Println(name, schema.Title)
			if schema.Ref != "" {

				schema.Ref = "jsonlite:" + path.Base(schema.Ref)
			}
		*/
		err = walkJSON(schema, func(elem jsonschema.JSONPather) error {
			if sch, ok := elem.(*jsonschema.Schema); ok {
				if sch.Ref != "" && sch.Ref[0] != '#' {
					// fmt.Printf("'%s'-'%s'\n", sch.Ref, strings.TrimSuffix(path.Base(sch.Ref), ".json"))
					sch.Ref = "jsonlite:" + strings.TrimSuffix(path.Base(sch.Ref), ".json")
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		jsonschema.DefaultSchemaPool["jsonlite:"+schema.Title] = &schema.Schema // TODO fill cache only once
	}

	// fetch references
	for _, schema := range store.Schemas() {
		err = schema.FetchRemoteReferences()
		if err != nil {
			return nil, errors.Wrap(err, "could not FetchRemoteReferences")
		}
	}

	return New(store)
}

// InsertStruct converts a Go struct to a map and inserts it.
func (db *ForensicStore) InsertStruct(item interface{}) (string, error) {
	ids, err := db.InsertStructBatch([]interface{}{item})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// InsertStructBatch adds a list of structs to the forensicstore.
func (db *ForensicStore) InsertStructBatch(items []interface{}) ([]string, error) {
	var ms []gostore.Item
	for _, item := range items {
		m := structs.Map(item)
		m = lower(m).(map[string]interface{})
		ms = append(ms, m)
	}

	return db.InsertBatch(ms)
}

func lower(f interface{}) interface{} {
	var hashes = map[string]bool{
		"MD5":        true,
		"MD6":        true,
		"RIPEMD-160": true,
		"SHA-1":      true,
		"SHA-224":    true,
		"SHA-256":    true,
		"SHA-384":    true,
		"SHA-512":    true,
		"SHA3-224":   true,
		"SHA3-256":   true,
		"SHA3-384":   true,
		"SHA3-512":   true,
		"SSDEEP":     true,
		"WHIRLPOOL":  true,
	}
	switch f := f.(type) {
	case []interface{}:
		for i := range f {
			if !isEmptyValue(reflect.ValueOf(f[i])) {
				f[i] = lower(f[i])
			}
		}
		return f
	case map[string]interface{}:
		lf := make(map[string]interface{}, len(f))
		for k, v := range f {
			if !isEmptyValue(reflect.ValueOf(v)) {
				if _, ok := hashes[k]; ok {
					lf[k] = lower(v)
				} else {
					lf[strcase.ToSnake(k)] = lower(v)
				}
			}
		}
		return lf
	default:
		return f
	}
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}
