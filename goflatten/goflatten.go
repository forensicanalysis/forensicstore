// Copyright (c) 2019 Nguyễn Quốc Đính
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
// Author(s): Nguyễn Quốc Đính, Jonas Plum
//
// This code was adapted from
// https://github.com/nqd/flat/blob/master/flat.go

// Package goflatten provides functions to flatten and unflatten Go maps.
package goflatten

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/imdario/mergo"
)

// Flatten the map, it returns a map one level deep
// regardless of how nested the original map was.
// By default, the flatten has Delimiter = ".", and
// no limitation of MaxDepth
func Flatten(nested map[string]interface{}) (flatmap map[string]interface{}, err error) {
	return flatten("", nested)
}

func flatten(prefix string, nested interface{}) (flatmap map[string]interface{}, err error) {
	flatmap = make(map[string]interface{})

	value := reflect.ValueOf(nested)

	if nested == nil {
		// flatmap[prefix] = nested
		return flatmap, nil
	}

	switch value.Type().Kind() {
	case reflect.Map:
		for _, k := range value.MapKeys() {
			// create new key
			newKey := fmt.Sprint(k.Interface())
			if prefix != "" {
				newKey = prefix + "." + newKey
			}
			fm1, fe := flatten(newKey, value.MapIndex(k).Interface())
			if fe != nil {
				err = fe
				return
			}
			update(flatmap, fm1)
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			newKey := strconv.Itoa(i)
			if prefix != "" {
				newKey = prefix + "." + newKey
			}
			fm1, fe := flatten(newKey, value.Index(i).Interface())
			if fe != nil {
				err = fe
				return
			}
			update(flatmap, fm1)
		}
	default:
		flatmap[prefix] = nested
	}
	return flatmap, nil
}

// update is the function that update to map with from
// example:
// to = {"hi": "there"}
// from = {"foo": "bar"}
// then, to = {"hi": "there", "foo": "bar"}
func update(to map[string]interface{}, from map[string]interface{}) {
	for kt, vt := range from {
		to[kt] = vt
	}
}

// Unflatten the map, it returns a nested map of a map
// By default, the flatten has Delimiter = "."
func Unflatten(flat map[string]interface{}) (nested map[string]interface{}, err error) {
	nested = make(map[string]interface{})

	for k, v := range flat {
		temp := uf(k, v).(map[string]interface{})
		err = mergo.Merge(&nested, temp)
		if err != nil {
			return
		}
	}

	walk(reflect.ValueOf(nested))

	return
}

func uf(k string, v interface{}) (n interface{}) {
	n = v

	keys := strings.Split(k, ".")

	for i := len(keys) - 1; i >= 0; i-- {
		temp := make(map[string]interface{})
		temp[keys[i]] = n
		n = temp
	}

	return
}

func walk(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			element := v.Index(i)
			update := walk(element)
			element.Set(update)
		}
		return v
	case reflect.Map:
		mapKeys := v.MapKeys()

		isList := true
		list := make([]interface{}, len(mapKeys))
		for _, k := range mapKeys {
			j, err := strconv.Atoi(k.String())
			if err != nil || j > len(mapKeys)-1 || list[j] != nil {
				isList = false
				break
			}
			list[j] = v.MapIndex(k).Interface()
		}

		for _, k := range v.MapKeys() {
			v.SetMapIndex(k, walk(v.MapIndex(k)))
		}
		if isList {
			return reflect.ValueOf(list)
		}
		return v
	default:
		return v
	}
}
