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
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

var (
	ProcessElementId = "process--920d7c41-0fef-4cf8-bce2-ead120f6b506"
	ProcessElement   = Element{
		"id":           ProcessElementId,
		"artifact":     "IPTablesRules",
		"type":         "process",
		"name":         "iptables",
		"created_time": "2016-01-20T14:11:25.550Z",
		"cwd":          "/root/",
		"command_line": "/sbin/iptables -L -n -v",
		"stdout_path":  "IPTablesRules/stdout",
		"stderr_path":  "IPTablesRules/stderr",
		"return_code":  float64(0),
	}
)

var exampleStore = "example1.forensicstore"

func setup(t *testing.T) string {
	dir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join("test", "forensicstore", exampleStore)
	dst := filepath.Join(dir, exampleStore)
	for _, name := range []string{"element.db", filepath.Join("WindowsAMCacheHveFile", "Amcache.hve"), filepath.Join("IPTablesRules", "stderr"), filepath.Join("IPTablesRules", "stdout"), filepath.Join("WMILogicalDisks", "stdout"), filepath.Join("WMILogicalDisks", "wmi"), filepath.Join("WMILogicalDisks", "stderr")} {
		CopyFile(t, filepath.Join(src, name), filepath.Join(dst, name))
	}

	return filepath.Join(dir, exampleStore)
}

func CopyFile(t *testing.T, src, dst string) {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	err = os.MkdirAll(filepath.Dir(dst), 0755)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(dst, input, 0644); err != nil {
		t.Fatal(err)
	}
}

func teardown(t *testing.T) {
	files, err := ioutil.ReadDir(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {
		if strings.HasPrefix(f.Name(), t.Name()) {
			os.Remove(f.Name())
		}
	}
}

func TestNew(t *testing.T) {
	tempDir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		remoteURL string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"New", args{tempDir}, false},
		{"Wrong URL", args{"foo\x00bar"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.args.remoteURL)
			defer os.Remove(tt.args.remoteURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestStore_Insert(t *testing.T) {
	foo := Element{"name": "foo", "type": "fo", "int": 0}
	bar := Element{"name": "bar", "type": "ba", "int": 2}
	baz := Element{"name": "baz", "type": "ba", "float": 0.1}
	bat := Element{"name": "bat", "type": "ba", "list": []string{}}
	bau := Element{"name": "bau", "type": "ba", "list": nil}

	testDir := setup(t)
	defer teardown(t)

	type fields struct {
		url string
	}
	type args struct {
		element Element
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{"Insert First", fields{testDir}, args{foo}, "fo--", false},
		{"Insert Second", fields{testDir}, args{bar}, "ba--", false},
		{"Insert Different Columns", fields{testDir}, args{baz}, "ba--", false},
		{"Insert Empty List", fields{testDir}, args{bat}, "ba--", false},
		{"Insert Element with nil", fields{testDir}, args{bau}, "ba--", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			got, err := db.Insert(tt.args.element)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Insert() error = %v, wantErr %v", err, tt.wantErr)
			} else if got[:4] != tt.want {
				t.Errorf("ForensicStore.Insert() = %v, want %v", got[:4], tt.want)
			}
		})
	}
}

func TestForensicStore_InsertStruct(t *testing.T) {
	testDir := setup(t)
	defer teardown(t)

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
			store, err := Open(testDir)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.InsertStruct(tt.args.element)
			if (err != nil) != tt.wantErr {
				t.Errorf("InsertStruct() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestStore_Get(t *testing.T) {
	log.Print("get")
	testDir := setup(t)
	defer teardown(t)

	type fields struct {
		url string
	}
	type args struct {
		id string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		wantElement Element
		wantErr     bool
	}{
		{"Get element", fields{testDir}, args{ProcessElementId}, ProcessElement, false},
		{"Get non existing", fields{testDir}, args{"process--16b02a2b-d1a1-4e79-aad6-2f2c1c286818"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Print("get2")
			db, err := Open(tt.fields.url)
			log.Print("get3")
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			// defer os.Remove(tt.fields.url)
			gotElement, err := db.Get(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.EqualValues(t, gotElement, tt.wantElement)
		})
	}
}

func TestStore_QueryStore(t *testing.T) {
	testDir := setup(t)
	defer teardown(t)

	type fields struct {
		url string
	}
	type args struct {
		query string
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantElements []Element
		wantErr      bool
	}{
		{"Query", fields{testDir}, args{"SELECT * FROM process WHERE name=\"iptables\""}, []Element{ProcessElement}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			defer os.Remove(tt.fields.url)
			gotElements, err := db.Query(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.Query() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.EqualValues(t, gotElements, tt.wantElements)
		})
	}
}

func TestStore_Select(t *testing.T) {
	testDir := setup(t)
	defer teardown(t)

	type fields struct {
		url string
	}
	type args struct {
		elementType string
		conditions  []map[string]string
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantElements int
		wantErr      bool
	}{
		{"Select", fields{testDir}, args{"file", nil}, 2, false},
		{"Select with filter", fields{testDir}, args{"file", []map[string]string{{"name": "foo.doc"}}}, 1, false},
		{"Select not existing", fields{testDir}, args{"xxx", nil}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			defer os.Remove(tt.fields.url)
			gotElements, err := db.Select(tt.args.elementType, tt.args.conditions)
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
	testDir := setup(t)
	defer teardown(t)

	type fields struct {
		url string
	}
	tests := []struct {
		name         string
		fields       fields
		wantElements int
		wantErr      bool
	}{
		{"All", fields{testDir}, 7, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			defer os.Remove(tt.fields.url)
			gotElements, err := db.All()
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.All() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// assert.EqualValues(t, gotElements, tt.wantElements)
			assert.Equal(t, tt.wantElements, len(gotElements))
		})
	}
}

/*
type MockColumnType struct {
	sql.ColumnType
	t reflect.Type
}

func (ci *MockColumnType) ScanType() reflect.Type {
	return ci.t
}

type MockRows struct {
	*sql.Rows
	i     int
	elements []Element
}

func NewMockRows() *MockRows {
	rs := MockRows{}
	rs.i = 2
	rs.elements = []Element{
		{"id": 1, "foo": map[string]interface{}{"bar": "post"}, "body": "hello"},
		{"id": 2, "foo": map[string]interface{}{"bar": "man"}, "body": "world"},
	}
	return &rs
}

func (rs *MockRows) Next() bool {
	rs.i--
	return rs.i > 0
}
func (rs *MockRows) Scan(dest ...interface{}) error {
	dest[0] = rs.elements[0]["id"]
	dest[0] = rs.elements[0]["foo"]
	dest[0] = rs.elements[0]["body"]
	return nil
}
func (rs *MockRows) ColumnTypeScanType(index int) reflect.Type {
	columns := []reflect.Type{
		reflect.TypeOf(1),
		reflect.TypeOf(map[string]interface{}{}),
		reflect.TypeOf(""),
	}

	return columns[index]
}
*/

func TestStore_rowsToElements(t *testing.T) {

	/* TODO create MockRows


	testDir := setup(t)
	defer teardown(t)

	type fields struct {
		url string
	}
	type args struct {
		rows *sql.Rows
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantElements []Element
		wantErr   bool
	}{
		{"Row to Elements", fields{testDir + EXAMPLE_STORE}, args{rows}, elements, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := New(tt.fields.url,  "type")
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			defer os.Remove(tt.fields.url)
			gotElements, err := db.rowsToElements(tt.args.rows)
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.rowsToElements() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.EqualValues(t, gotElements, tt.wantElements)
		})
	}
	*/
}

func TestStore_getTables(t *testing.T) {
	testDir := setup(t)
	defer teardown(t)

	expectedTables := map[string]map[string]string{
		"directory":            {"atime": "TEXT", "artifact": "TEXT", "ctime": "TEXT", "mtime": "TEXT", "path": "TEXT", "type": "TEXT", "id": "TEXT"},
		"file":                 {"atime": "TEXT", "artifact": "TEXT", "ctime": "TEXT", "export_path": "TEXT", "hashes.MD5": "TEXT", "hashes.SHA-1": "TEXT", "mtime": "TEXT", "name": "TEXT", "origin.path": "TEXT", "origin.volume": "TEXT", "size": "INTEGER", "type": "TEXT", "id": "TEXT"},
		"process":              {"artifact": "TEXT", "command_line": "TEXT", "created_time": "TEXT", "cwd": "TEXT", "name": "TEXT", "return_code": "INTEGER", "stderr_path": "TEXT", "stdout_path": "TEXT", "type": "TEXT", "id": "TEXT", "wmi_path": "TEXT"},
		"windows-registry-key": {"artifact": "TEXT", "key": "TEXT", "modified_time": "TEXT", "type": "TEXT", "id": "TEXT", "values.0.data": "TEXT", "values.0.data_type": "TEXT", "values.0.name": "TEXT"},
	}

	type fields struct {
		url string
	}
	tests := []struct {
		name    string
		fields  fields
		want    map[string]map[string]string
		wantErr bool
	}{
		{"Get Tables", fields{testDir}, expectedTables, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			defer os.Remove(tt.fields.url)
			got, err := db.getTables()
			if (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.getTables() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ForensicStore.getTables() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestStore_ensureTable(t *testing.T) {
	testDir := setup(t)
	defer teardown(t)

	type fields struct {
		url string
	}
	type args struct {
		flatElement Element
		element     Element
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"Ensure table", fields{testDir}, args{Element{"foo": 1, "type": "bar"}, Element{"foo": 1, "type": "bar"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			defer os.Remove(tt.fields.url)
			if err := db.ensureTable(tt.args.flatElement, tt.args.element); (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.ensureTable() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStore_createTable(t *testing.T) {
	testDir := setup(t)
	defer teardown(t)

	type fields struct {
		url string
	}
	type args struct {
		flatElement Element
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"Create table", fields{testDir}, args{Element{"foo": 1, "type": "bar"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			defer os.Remove(tt.fields.url)
			if err := db.createTable(tt.args.flatElement); (err != nil) != tt.wantErr {
				t.Errorf("ForensicStore.createTable() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getSQLDataType(t *testing.T) {
	type args struct {
		value interface{}
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"Get SQL Data Type INTEGER", args{1}, "INTEGER"},
		{"Get SQL Data Type TEXT", args{"foo"}, "TEXT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSQLDataType(tt.args.value); got != tt.want {
				t.Errorf("getSQLDataType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStore_Validate(t *testing.T) {
	testDir := setup(t)

	type fields struct {
		url string
	}
	tests := []struct {
		name    string
		fields  fields
		wantE   []string
		wantErr bool
	}{
		{"Validate valid", fields{testDir}, []string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			defer os.Remove(tt.fields.url)

			gotE, err := db.Validate()
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
	testDir := setup(t)

	testElement1 := map[string]interface{}{
		"id":   "file--920d7c41-0fef-4cf8-bce2-ead120f6b506",
		"type": "file",
		"name": "foo.txt",
		"hashes": map[string]interface{}{
			"MD5": "0356a89e11fcbed1288a0553377541af",
		},
	}
	testElement2 := Element{
		"id":   "file--920d7c41-0fef-4cf8-bce2-ead120f6b506",
		"type": "file",
		"foo":  "foo.txt",
	}

	type fields struct {
		url string
	}
	type args struct {
		element Element
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantFlaws int
		wantErr   bool
	}{
		{"valid", fields{testDir}, args{testElement1}, 0, false},
		{"invalid", fields{testDir}, args{testElement2}, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			gotFlaws, err := db.validateElementSchema(tt.args.element)
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
	testDir := setup(t)

	type fields struct {
		url string
	}
	type args struct {
		filePath string
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantStorePath string
		wantData      []byte
		wantErr       bool
	}{
		{"first file", fields{testDir}, args{"test.txt"}, "test.txt", []byte("foo"), false},
		{"second file", fields{testDir}, args{"test.txt"}, "test_0.txt", []byte("bar"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(tt.fields.url)
			if err != nil || db == nil {
				t.Fatalf("Database could not be created %v\n", err)
			}

			gotStorePath, gotFile, err := db.StoreFile(tt.args.filePath)
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

			load, err := db.LoadFile(gotStorePath)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ioutil.ReadAll(load)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(b, tt.wantData) {
				t.Errorf("ForensicStore.StoreFile() gotFile = %v, want %v", b, tt.wantData)
			}
		})
	}
}
