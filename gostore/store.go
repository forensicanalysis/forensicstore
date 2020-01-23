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

// Package gostore provides an interface for data storage. This interface is
// implemented by the gojsonlite library.
package gostore

import (
	"github.com/qri-io/jsonschema"
	"github.com/spf13/afero"
)

// Item is a single element in the database.
type Item map[string]interface{}

// Store is an interface for a storage structure that can store Items and files.
type Store interface {
	afero.Fs

	Insert(item Item) (string, error)
	InsertBatch(items []Item) ([]string, error)
	Get(id string) (item Item, err error)
	Update(id string, partialItem Item) (string, error)
	Select(itemType string) (items []Item, err error)
	All() (items []Item, err error)
	Close() (err error)

	StoreFile(filePath string) (storePath string, file afero.File, err error)
	LoadFile(path string) (file afero.File, err error)

	ImportJSONLite(url string) (err error)
	ExportJSONLite(url string) (err error)

	Validate() (e []string, err error)
	SetSchema(id string, schema *jsonschema.RootSchema) (err error)
}
