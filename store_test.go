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
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type element map[string]interface{}

func jsons(e element) []byte {
	b, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	ProcessElementId = "process--920d7c41-0fef-4cf8-bce2-ead120f6b506"
	ProcessElement   = []byte(`{
		"id":           "process--920d7c41-0fef-4cf8-bce2-ead120f6b506",
		"artifact":     "IPTablesRules",
		"type":         "process",
		"name":         "iptables",
		"created_time": "2016-01-20T14:11:25.550Z",
		"cwd":          "/root/",
		"command_line": "/sbin/iptables -L -n -v",
		"stdout_path":  "IPTablesRules/stdout",
		"stderr_path":  "IPTablesRules/stderr",
		"return_code":  0
	}`)
)

func TestExtract(t *testing.T) {
	_, teardown := setupUrl(t, "test.forensicstore")
	defer teardown()
}

func setup(t *testing.T) (*ForensicStore, func() error) {
	return setupUrl(t, ":memory:")
}

func setupUrl(t *testing.T, url string) (*ForensicStore, func() error) {
	store, teardown, err := New(url)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.InsertStruct(Process{
		ID:          "process--920d7c41-0fef-4cf8-bce2-ead120f6b506",
		Artifact:    "IPTablesRules",
		Type:        "process",
		Name:        "iptables",
		CreatedTime: "2016-01-20T14:11:25.550Z",
		Cwd:         "/root/",
		CommandLine: "/sbin/iptables -L -n -v",
		StdoutPath:  "IPTablesRules/stdout",
		StderrPath:  "IPTablesRules/stderr",
		ReturnCode:  0,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.InsertStruct(Process{
		ID:          "process--9da4aa39-53b8-412e-b3cd-6b26c772ad4d",
		Artifact:    "WMILogicalDisks",
		Type:        "process",
		Name:        "powershell",
		CreatedTime: "2016-01-20T14:11:25.550Z",
		Cwd:         "/root/",
		CommandLine: "powershell \"gwmi -Query \\\"SELECT * FROM Win32_LogicalDisk\\\"\"",
		StdoutPath:  "WMILogicalDisks/stdout",
		StderrPath:  "WMILogicalDisks/stderr",
		ReturnCode:  0,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.InsertStruct(RegistryKey{
		ID:           "windows-registry-key--286a78b9-e8e1-4d89-9a3b-6001c817ea64",
		Artifact:     "WindowsRunKeys",
		Type:         "windows-registry-key",
		Key:          "HKEY_USERS\\S-1-5-21-7623811015-3361044348-030300820-1013\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		ModifiedTime: "2013-11-19T22:46:05.668Z",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.InsertStruct(RegistryKey{
		ID:       "windows-registry-key--4125428d-cfad-466d-8f2d-a72f9aac6687",
		Artifact: "WindowsCodePage",
		Type:     "windows-registry-key",
		Key:      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Nls\\CodePage",
		Values: []RegistryValue{{
			Name:     "ACP",
			Data:     "1252",
			DataType: "REG_SZ",
		}},
		ModifiedTime: "2009-07-14T04:34:14.225Z",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.InsertStruct(File{
		ID:       "file--ddc3b32f-a1ea-4888-87ca-5591773f6be3",
		Artifact: "WindowsAMCacheHveFile",
		Type:     "file",
		Size:     123,
		Name:     "Amcache.hve",
		Ctime:    "2014-09-11T21:50:18.301Z",
		Mtime:    "2014-09-11T21:50:18.301Z",
		Atime:    "2014-09-11T21:50:18.301Z",
		Origin: map[string]interface{}{
			"volumne": 2,
			"path":    "C:\\Windows\\appcompat\\Programs\\Amcache.hve",
		},
		ExportPath: "WindowsAMCacheHveFile/Amcache.hve",
		Hashes: map[string]interface{}{
			"MD5":   "9b573b2e4c4b91558f6afd65262a6fb9",
			"SHA-1": "932567a1cfc045b729abdb52ed6c5c6acf59f369",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.InsertStruct(File{
		ID:       "file--7408798b-6f09-49dd-a3a0-c54fba59c38c",
		Artifact: "WindowsUserDownloadsDirectory",
		Type:     "file",
		Size:     123,
		Name:     "foo.doc",
		Ctime:    "2014-09-11T21:50:18.301Z",
		Mtime:    "2014-09-11T21:50:18.301Z",
		Atime:    "2014-09-11T21:50:18.301Z",
		Origin: map[string]interface{}{
			"volumne": 2,
			"path":    "C:\\Users\\bob\\Downloads\\foo.doc",
		},
		ExportPath: "WindowsAMCacheHveFile/Amcache.hve",
		Hashes: map[string]interface{}{
			"MD5":   "9b573b2e4c4b91558f6afd65262a6fb9",
			"SHA-1": "932567a1cfc045b729abdb52ed6c5c6acf59f369",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.InsertStruct(Directory{
		ID:       "directory--ed070d8c-c8d9-40ab-ae18-3f6b6725b7a7",
		Artifact: "WindowsEnvironmentVariableProgramFiles",
		Type:     "directory",
		Path:     "C:\\Program Files",
		Ctime:    "2014-09-11T21:50:18.301Z",
		Mtime:    "2014-09-11T21:50:18.301Z",
		Atime:    "2014-09-11T21:50:18.301Z",
	})
	if err != nil {
		t.Fatal(err)
	}

	store.Fs.Mkdir("/", 0755)
	store.Fs.Mkdir("/WindowsAMCacheHveFile", 0755)
	store.Fs.Mkdir("/IPTablesRules", 0755)
	store.Fs.Mkdir("/WMILogicalDisks", 0755)

	f, _ := store.Fs.Create("/WindowsAMCacheHveFile/Amcache.hve")
	f.WriteString(strings.Repeat("A", 123))
	err = f.Close()
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"/IPTablesRules/stderr",
		"/IPTablesRules/stdout",
		"/WMILogicalDisks/stderr",
		"/WMILogicalDisks/stdout",
	} {
		f, err = store.Fs.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	return store, teardown
}

func TestNew(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "newforensicstore")
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		url string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"New", args{filepath.Join(tempDir, "my.store")}, false},
		// {"Wrong URL", args{"foo\x00bar"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, teardown, err := New(tt.args.url)
			defer teardown()
			defer os.Remove(tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestStore_Insert(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	foo := jsons(element{"name": "foo", "type": "fo", "int": 0})
	bar := jsons(element{"name": "bar", "type": "ba", "int": 2})
	baz := jsons(element{"name": "baz", "type": "ba", "float": 0.1})
	bat := jsons(element{"name": "bat", "type": "ba", "list": []string{}})
	bau := jsons(element{"name": "bau", "type": "ba", "list": nil})

	type args struct {
		element JSONElement
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"Insert First", args{foo}, "fo--", false},
		{"Insert Second", args{bar}, "ba--", false},
		{"Insert Different Columns", args{baz}, "ba--", false},
		{"Insert Empty List", args{bat}, "ba--", false},
		{"Insert Element with nil", args{bau}, "ba--", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.Insert(tt.args.element)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Insert() error = %v, wantErr %v", err, tt.wantErr)
			} else if got[:4] != tt.want {
				t.Errorf("ForensicStore.Insert() = %v, want %v", got[:4], tt.want)
			}
		})
	}
}

func TestForensicStore_InsertStruct(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	myfile := NewFile()
	myfile.Name = "test.txt"

	myfile2 := struct {
		Type string
		Name int
	}{"file", 1}

	myfile3 := File{Type: "file"}

	type args struct {
		element interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{myfile}, false},
		{"wrong schema", args{myfile2}, true},
		{"empty file element", args{myfile3}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.InsertStruct(tt.args.element)
			if (err != nil) != tt.wantErr {
				t.Errorf("InsertStruct() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestStore_Get(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	type args struct {
		id string
	}
	tests := []struct {
		name        string
		args        args
		wantElement JSONElement
		wantErr     bool
	}{
		{"Get element", args{ProcessElementId}, ProcessElement, false},
		{"Get non existing", args{"process--16b02a2b-d1a1-4e79-aad6-2f2c1c286818"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotElement, err := store.Get(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			assert.JSONEq(t, string(gotElement), string(tt.wantElement))
		})
	}
}

func TestStore_QueryStore(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	type args struct {
		query string
	}
	tests := []struct {
		name         string
		args         args
		wantElements []JSONElement
		wantErr      bool
	}{
		{"Query", args{"SELECT json FROM elements WHERE json_extract(json, '$.name') = 'iptables'"}, []JSONElement{ProcessElement}, false},
		{"FTS Query", args{"SELECT json FROM elements WHERE elements = 'IPTablesRules'"}, []JSONElement{ProcessElement}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotElements, err := store.Query(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Query() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.JSONEq(t, string(tt.wantElements[0]), string(gotElements[0]))
		})
	}
}

func TestStore_Search(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	type args struct {
		query string
	}
	tests := []struct {
		name         string
		args         args
		wantElements []JSONElement
		wantErr      bool
	}{
		{"Search", args{"IPTablesRules"}, []JSONElement{ProcessElement}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotElements, err := store.Search(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Search() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.JSONEq(t, string(tt.wantElements[0]), string(gotElements[0]))
		})
	}
}

func TestStore_Select(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	type args struct {
		conditions []map[string]string
	}
	tests := []struct {
		name         string
		args         args
		wantElements int
		wantErr      bool
	}{
		{"Select", args{[]map[string]string{{"type": "file"}}}, 2, false},
		{"Select with filter", args{[]map[string]string{{"type": "file", "name": "foo.doc"}}}, 1, false},
		{"Select not existing", args{[]map[string]string{{"type": "xxx"}}}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotElements, err := store.Select(tt.args.conditions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Select() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// assert.EqualValues(t, gotElements, tt.wantElements) // TODO check array content
			assert.EqualValues(t, tt.wantElements, len(gotElements))
		})
	}
}

func TestStore_All(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	tests := []struct {
		name         string
		wantElements int
		wantErr      bool
	}{
		{"All", 7, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotElements, err := store.All()
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.All() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// assert.EqualValues(t, gotElements, tt.wantElements)
			assert.Equal(t, tt.wantElements, len(gotElements))
		})
	}
}

func TestStore_Validate(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	tests := []struct {
		name    string
		wantE   []string
		wantErr bool
	}{
		{"Validate valid", []string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotE, err := store.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotE, tt.wantE) {
				t.Errorf("ForensicStore.Validate() = \n%#v\n, want \n%#v", gotE, tt.wantE)
			}
		})
	}
}

func TestStore_validateElementSchema(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	testElement1 := jsons(map[string]interface{}{
		"id":   "file--920d7c41-0fef-4cf8-bce2-ead120f6b506",
		"type": "file",
		"name": "foo.txt",
		"hashes": map[string]interface{}{
			"MD5": "0356a89e11fcbed1288a0553377541af",
		},
	})
	testElement2 := jsons(element{
		"id":   "file--920d7c41-0fef-4cf8-bce2-ead120f6b506",
		"type": "file",
		"foo":  "foo.txt",
	})

	type args struct {
		element JSONElement
	}
	tests := []struct {
		name      string
		args      args
		wantFlaws int
		wantErr   bool
	}{
		{"valid", args{testElement1}, 0, false},
		{"invalid", args{testElement2}, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFlaws, err := store.validateElementSchema(tt.args.element)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.validateElementSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(gotFlaws) != tt.wantFlaws {
				t.Errorf("ForensicStore.validateElementSchema() = %v, want %v", gotFlaws, tt.wantFlaws)
			}
		})
	}
}

func TestStore_StoreFile(t *testing.T) {
	store, teardown := setup(t)
	defer teardown()

	type args struct {
		filePath string
	}
	tests := []struct {
		name          string
		args          args
		wantStorePath string
		wantData      []byte
		wantErr       bool
	}{
		{"first file", args{"test.txt"}, "test.txt", []byte("foo"), false},
		{"second file", args{"test.txt"}, "test_0.txt", []byte("bar"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStorePath, gotFile, err := store.StoreFile(tt.args.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.StoreFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			_, err = gotFile.Write(tt.wantData)
			if err != nil {
				t.Fatal(err)
			}
			err = gotFile.Close()
			if err != nil {
				t.Fatal(err)
			}

			if filepath.Base(gotStorePath) != tt.wantStorePath {
				t.Errorf("ForensicStore.StoreFile() gotStorePath = %v, want %v", filepath.Base(gotStorePath), tt.wantStorePath)
			}

			load, err := store.LoadFile(gotStorePath)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ioutil.ReadAll(load)
			if err != nil {
				t.Fatal(err)
			}

			err = load.Close()
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(b, tt.wantData) {
				t.Errorf("ForensicStore.StoreFile() gotFile = %v, want %v", b, tt.wantData)
			}
		})
	}
}
