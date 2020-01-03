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

package goflatten

import (
	"reflect"
	"testing"
)

func TestFlatten(t *testing.T) {
	type args struct {
		object map[string]interface{}
	}
	tests := []struct {
		name           string
		args           args
		wantFlatObject map[string]interface{}
		wantErr        bool
	}{
		{"Flatten", args{map[string]interface{}{"foo": []interface{}{"a", 1}}}, map[string]interface{}{"foo.0": "a", "foo.1": 1}, false},
		{"Flatten Nested", args{map[string]interface{}{"foo": map[string]interface{}{"a": 1}}}, map[string]interface{}{"foo.a": 1}, false},
		{"Flatten Nested String", args{map[string]interface{}{"foo": map[string]string{"a": "b"}}}, map[string]interface{}{"foo.a": "b"}, false},
		{"Flatten Empty Map", args{map[string]interface{}{"foo": map[string]string{}}}, map[string]interface{}{}, false},
		{"Flatten Empty Slice", args{map[string]interface{}{"foo": map[string]string{}}}, map[string]interface{}{}, false},
		{"Flatten Empty String", args{map[string]interface{}{"foo": ""}}, map[string]interface{}{"foo": ""}, false},
		{"Flatten Nil", args{map[string]interface{}{"foo": nil}}, map[string]interface{}{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFlatObject, err := Flatten(tt.args.object)
			if (err != nil) != tt.wantErr {
				t.Errorf("Flatten() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFlatObject, tt.wantFlatObject) {
				t.Errorf("Flatten() = %v, want %v", gotFlatObject, tt.wantFlatObject)
			}
		})
	}
}

func TestUnflatten(t *testing.T) {
	type args struct {
		object map[string]interface{}
	}
	tests := []struct {
		name           string
		args           args
		wantFlatObject map[string]interface{}
		wantErr        bool
	}{
		{"Unflatten List", args{map[string]interface{}{"foo.0": "a", "foo.1": 1}}, map[string]interface{}{"foo": []interface{}{"a", 1}}, false},
		{"Unflatten No List", args{map[string]interface{}{"foo.1": "a", "foo.2": 1}}, map[string]interface{}{"foo": map[string]interface{}{"1": "a", "2": 1}}, false},
		{"Unflatten Ordered List", args{map[string]interface{}{"foo.0": 1, "foo.1": 2, "foo.2": 3, "foo.3": 4}}, map[string]interface{}{"foo": []interface{}{1, 2, 3, 4}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFlatObject, err := Unflatten(tt.args.object)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unflatten() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFlatObject, tt.wantFlatObject) {
				t.Errorf("Unflatten() = %v, want %v", gotFlatObject, tt.wantFlatObject)
			}
		})
	}
}
