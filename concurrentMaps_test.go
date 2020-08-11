// Copyright (c) 2020 Jonas Plum
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
	"reflect"
	"testing"
)

func Test_typeMap_add(t *testing.T) {
	type args struct {
		name  string
		field string
	}
	tests := []struct {
		name string
		args args
	}{
		{"add", args{name: "file", field: "name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := newTypeMap()
			rm.add(tt.args.name, tt.args.field)
		})
	}
}

func Test_typeMap_addAll(t *testing.T) {
	type args struct {
		name   string
		fields map[string]interface{}
	}
	tests := []struct {
		name string
		args args
	}{
		{"add new", args{name: "file", fields: map[string]interface{}{"file": true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := newTypeMap()
			rm.addAll(tt.args.name, tt.args.fields)
		})
	}
}

func Test_typeMap_all(t *testing.T) {
	tests := []struct {
		name string
		want map[string]map[string]bool
	}{
		{"all", map[string]map[string]bool{"file": {"name": true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := newTypeMap()
			rm.add("file", "name")
			if got := rm.all(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("all() = %v, want %v", got, tt.want)
			}
		})
	}
}
