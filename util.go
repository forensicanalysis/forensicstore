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

// Package forensicstore provides functions to handle forensicstores.
package forensicstore

import (
	"reflect"

	"github.com/iancoleman/strcase"
	"github.com/qri-io/jsonschema"
)

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
