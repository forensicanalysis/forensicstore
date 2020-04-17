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

package goforensicstore

import (
	"reflect"
	"strings"
	"testing"
)

func TestFile_AddError(t *testing.T) {
	type args struct {
		err string
	}
	tests := []struct {
		name string
		i    File
		args args
		want File
	}{
		{"Add Error", File{}, args{"error"}, File{Errors: []interface{}{"error"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.AddError(tt.args.err); !reflect.DeepEqual(got, &tt.want) {
				t.Errorf("File.AddError() = %v, want %v", got, &tt.want)
			}
		})
	}
}

func TestDirectory_AddError(t *testing.T) {
	type args struct {
		err string
	}
	tests := []struct {
		name string
		i    Directory
		args args
		want Directory
	}{
		{"Add Error", Directory{}, args{"error"}, Directory{Errors: []interface{}{"error"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.AddError(tt.args.err); !reflect.DeepEqual(got, &tt.want) {
				t.Errorf("Directory.AddError() = %v, want %v", got, &tt.want)
			}
		})
	}
}

func TestRegistryValue_AddError(t *testing.T) {
	type args struct {
		err string
	}
	tests := []struct {
		name string
		i    RegistryValue
		args args
		want RegistryValue
	}{
		{"Add Error", RegistryValue{}, args{"error"}, RegistryValue{Errors: []interface{}{"error"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.AddError(tt.args.err); !reflect.DeepEqual(got, &tt.want) {
				t.Errorf("RegistryValue.AddError() = %v, want %v", got, &tt.want)
			}
		})
	}
}

func TestRegistryKey_AddError(t *testing.T) {
	type args struct {
		err string
	}
	tests := []struct {
		name string
		i    RegistryKey
		args args
		want RegistryKey
	}{
		{"Add Error", RegistryKey{}, args{"error"}, RegistryKey{Errors: []interface{}{"error"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.AddError(tt.args.err); !reflect.DeepEqual(got, &tt.want) {
				t.Errorf("RegistryKey.AddError() = %v, want %v", got, &tt.want)
			}
		})
	}
}

func TestProcess_AddError(t *testing.T) {
	type args struct {
		err string
	}
	tests := []struct {
		name string
		i    Process
		args args
		want Process
	}{
		{"Add Error", Process{}, args{"error"}, Process{Errors: []interface{}{"error"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.i.AddError(tt.args.err); !reflect.DeepEqual(got, &tt.want) {
				t.Errorf("Process.AddError() = %v, want %v", got, &tt.want)
			}
		})
	}
}

func TestNewDirectory(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"new Directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDirectory()

			if got.Type != "directory" {
				t.Errorf("Directory.Type must be 'directory'")
			}

			if !strings.HasPrefix(got.ID, "directory--") {
				t.Errorf("Directory.ID must start with 'directory--'")
			}
		})
	}
}
func TestNewFile(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"new File"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewFile()

			if got.Type != "file" {
				t.Errorf("File.Type must be 'file'")
			}

			if !strings.HasPrefix(got.ID, "file--") {
				t.Errorf("File.ID must start with 'file--'")
			}
		})
	}
}

func TestNewRegistryKey(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"new RegistryKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRegistryKey()

			if got.Type != "windows-registry-key" {
				t.Errorf("RegistryKey.Type must be 'windows-registry-key'")
			}

			if !strings.HasPrefix(got.ID, "windows-registry-key--") {
				t.Errorf("RegistryKey.ID must start with 'windows-registry-key--'")
			}
		})
	}
}

func TestNewRegistryValue(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"new RegistryValue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = NewRegistryValue()
		})
	}
}

func TestNewProcess(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"new Process"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewProcess()

			if got.Type != "process" {
				t.Errorf("Process.Type must be 'process'")
			}

			if !strings.HasPrefix(got.ID, "process--") {
				t.Errorf("Process.ID must start with 'process--'")
			}
		})
	}
}
