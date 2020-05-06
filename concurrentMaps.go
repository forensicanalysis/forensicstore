/*
 * Copyright (c) 2020 Siemens AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Author(s): Jonas Plum
 */

package forensicstore

import (
	"sync"

	"github.com/qri-io/jsonschema"
)

type typeMap struct {
	sync.RWMutex
	changed bool
	types   map[string]map[string]bool
}

func newTypeMap() *typeMap {
	return &typeMap{
		changed: false,
		types:   map[string]map[string]bool{},
	}
}

func (rm *typeMap) all() map[string]map[string]bool {
	return rm.types
}

func (rm *typeMap) add(name, field string) {
	rm.Lock()
	if _, ok := rm.types[name]; !ok {
		rm.types[name] = map[string]bool{}
	}
	if _, ok := rm.types[name][field]; !ok {
		rm.types[name][field] = true
		rm.changed = true
	}

	rm.Unlock()
}

func (rm *typeMap) addAll(name string, fields map[string]interface{}) {
	rm.Lock()
	if _, ok := rm.types[name]; !ok {
		rm.types[name] = map[string]bool{}
	}
	for field := range fields {
		if _, ok := rm.types[name][field]; !ok {
			rm.types[name][field] = true
			rm.changed = true
		}
	}
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
