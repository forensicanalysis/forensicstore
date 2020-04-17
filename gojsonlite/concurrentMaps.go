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

package gojsonlite

import (
	"sync"

	"github.com/qri-io/jsonschema"
)

type tableMap struct {
	sync.RWMutex
	internal map[string]map[string]string
}

func newTableMap() *tableMap {
	return &tableMap{
		internal: make(map[string]map[string]string),
	}
}

func (rm *tableMap) load(key string) (value map[string]string, ok bool) {
	rm.RLock()
	result, ok := rm.internal[key]
	rm.RUnlock()
	return result, ok
}

func (rm *tableMap) store(key string, value map[string]string) {
	rm.Lock()
	rm.internal[key] = value
	rm.Unlock()
}

func (rm *tableMap) innerstore(key, innerkey, value string) {
	rm.Lock()
	rm.internal[key][innerkey] = value
	rm.Unlock()
}

type schemaMap struct {
	sync.RWMutex
	internal map[string]*jsonschema.RootSchema
}

func newSchemaMap() *schemaMap {
	return &schemaMap{
		internal: make(map[string]*jsonschema.RootSchema),
	}
}

func (rm *schemaMap) load(key string) (value *jsonschema.RootSchema, ok bool) {
	rm.RLock()
	result, ok := rm.internal[key]
	rm.RUnlock()
	return result, ok
}

func (rm *schemaMap) store(key string, value *jsonschema.RootSchema) {
	rm.Lock()
	rm.internal[key] = value
	rm.Unlock()
}

func (rm *schemaMap) values() (values []*jsonschema.RootSchema) {
	rm.Lock()
	for _, value := range rm.internal {
		values = append(values, value)
	}
	rm.Unlock()
	return values
}
