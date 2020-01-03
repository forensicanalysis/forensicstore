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
	"log"
)

// File implements a STIX 2.0 File Object
type File struct {
	Artifact   string                 `json:"artifact,omitempty"`
	Type       string                 `json:"type"`
	Hashes     map[string]interface{} `json:"hashes,omitempty"`
	Size       float64                `json:"size,omitempty"`
	Name       string                 `json:"name"`
	Created    string                 `json:"created,omitempty"`
	Modified   string                 `json:"modified,omitempty"`
	Accessed   string                 `json:"accessed,omitempty"`
	Origin     map[string]interface{} `json:"origin,omitempty"`
	ExportPath string                 `json:"export_path,omitempty"`
	Errors     []interface{}          `json:"errors,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// Directory implements a STIX 2.0 Directory Object
type Directory struct {
	Artifact string        `json:"artifact,omitempty"`
	Type     string        `json:"type"`
	Path     string        `json:"path"`
	Created  string        `json:"created,omitempty"`
	Modified string        `json:"modified,omitempty"`
	Accessed string        `json:"accessed,omitempty"`
	Errors   []interface{} `json:"errors,omitempty"`
}

// RegistryValue implements a STIX 2.0 Windows™ Registry Value Type
type RegistryValue struct {
	Name     string        `json:"name"`
	Data     string        `json:"data,omitempty"`
	DataType string        `json:"data_type,omitempty"`
	Errors   []interface{} `json:"errors,omitempty"`
}

// RegistryKey implements a STIX 2.0 Windows™ Registry Key Object
type RegistryKey struct {
	Artifact string          `json:"artifact,omitempty"`
	Type     string          `json:"type"`
	Key      string          `json:"key"`
	Values   []RegistryValue `json:"values,omitempty"`
	Modified string          `json:"modified,omitempty"`
	Errors   []interface{}   `json:"errors,omitempty"`
}

// Process implements a STIX 2.0 Process Object
type Process struct {
	Artifact    string        `json:"artifact,omitempty"`
	Type        string        `json:"type"`
	Name        string        `json:"name,omitempty"`
	Created     string        `json:"created,omitempty"`
	Cwd         string        `json:"cwd,omitempty"`
	Arguments   []interface{} `json:"arguments,omitempty"`
	CommandLine string        `json:"command_line,omitempty"`
	StdoutPath  string        `json:"stdout_path,omitempty"`
	StderrPath  string        `json:"stderr_path,omitempty"`
	WMI         []interface{} `json:"wmi,omitempty"`
	ReturnCode  float64       `json:"return_code,omitempty"`
	Errors      []interface{} `json:"errors,omitempty"`
}

// AddError adds an error string to a File and returns this File.
func (i *File) AddError(err string) *File {
	log.Print(err)
	i.Errors = append(i.Errors, err)
	return i
}

// AddError adds an error string to a Directory and returns this Directory.
func (i *Directory) AddError(err string) *Directory {
	log.Print(err)
	i.Errors = append(i.Errors, err)
	return i
}

// AddError adds an error string to a RegistryValue and returns this RegistryValue.
func (i *RegistryValue) AddError(err string) *RegistryValue {
	log.Print(err)
	i.Errors = append(i.Errors, err)
	return i
}

// AddError adds an error string to a RegistryKey and returns this RegistryKey.
func (i *RegistryKey) AddError(err string) *RegistryKey {
	log.Print(err)
	i.Errors = append(i.Errors, err)
	return i
}

// AddError adds an error string to a Process and returns this Process.
func (i *Process) AddError(err string) *Process {
	log.Print(err)
	i.Errors = append(i.Errors, err)
	return i
}
