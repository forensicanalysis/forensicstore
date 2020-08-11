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
