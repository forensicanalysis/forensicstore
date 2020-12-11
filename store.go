// Copyright (c) 2020 Siemens AG
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

// Package forensicstore can create,
// access and process forensic artifacts bundled in so called forensicstores
// (a database for forensic artifacts).
package forensicstore

import (
	"crypto/md5"  // #nosec
	"crypto/sha1" // #nosec
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"crawshaw.io/sqlite"
	"github.com/fatih/structs"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"github.com/tidwall/gjson"

	"github.com/forensicanalysis/forensicstore/sqlitefs"
)

const Version = 3
const elementaryApplicationID = 0x656c656d
const elementaryApplicationIDDirFS = 0x656c7a70
const discriminator = "type"

// The ForensicStore is a central storage for elements in digital forensic
// investigations. It stores any piece of information in the investigation and
// serves as a single source of truth for the data. Cases, artifacts, evidence,
// meta data, bookmarks etc. can be stored in the forensicstore. Larger binary
// objects like files are usually stored outside the forensicstore and references
// from the forensicstore.
type ForensicStore struct {
	Fs         afero.Fs
	connection *sqlite.Conn
	types      *typeMap
}

var ErrStoreExists = fmt.Errorf("store already exists")
var ErrStoreNotExists = fmt.Errorf("store does not exist")

// New creates a new Forensicstore.
func New(url string) (store *ForensicStore, teardown func() error, err error) { // nolint:gocyclo
	return open(url, true, elementaryApplicationID)
}

// New creates a new Forensicstore.
func NewDirFS(url string) (store *ForensicStore, teardown func() error, err error) { // nolint:gocyclo
	return open(url, true, elementaryApplicationIDDirFS)
}

// Open opens an existing Forensicstore.
func Open(url string) (store *ForensicStore, teardown func() error, err error) { // nolint:gocyclo
	return open(url, false, -1)
}

func (store *ForensicStore) pragma(name string) (int64, error) {
	stmt, err := store.connection.Prepare("PRAGMA " + name)
	if err != nil {
		return 0, err
	}
	_, err = stmt.Step()
	if err != nil {
		return 0, err
	}
	i := stmt.GetInt64(name)
	return i, stmt.Finalize()
}

func (store *ForensicStore) setPragma(name string, i int64) error {
	stmt, err := store.connection.Prepare("PRAGMA " + name + " = " + fmt.Sprint(i))
	if err != nil {
		return err
	}
	_, err = stmt.Step()
	if err != nil {
		return err
	}
	return stmt.Finalize()
}

func open(storeURL string, create bool, applicationID int64) (store *ForensicStore, teardown func() error, err error) { // nolint:gocyclo,funlen,gocognit,lll
	if storeURL != "file::memory:?mode=memory" {
		storeURL = strings.TrimRight(storeURL, "/")
		if !strings.HasSuffix(storeURL, ".forensicstore") {
			return nil, nil, errors.New("File needs to end with '.forensicstore'")
		}

		exists := true
		_, err := os.Stat(storeURL)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, nil, err
			}
			exists = false
		}

		if create && exists {
			return nil, nil, ErrStoreExists
		}
		if !create && !exists {
			return nil, nil, ErrStoreNotExists
		}

		if create {
			err = os.MkdirAll(path.Dir(storeURL), 0750)
			if err != nil {
				return nil, nil, err
			}

			log.Printf("Creating store %s", storeURL)
			_, err := os.Create(storeURL)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	store = &ForensicStore{}

	store.connection, err = sqlite.OpenConn(storeURL, 0)
	if err != nil {
		return nil, nil, err
	}

	switch applicationID {
	case elementaryApplicationIDDirFS:
		osFS := afero.NewOsFs()
		store.Fs = afero.NewBasePathFs(osFS, strings.TrimSuffix(storeURL, ".forensicstore"))
	case elementaryApplicationID:
		fallthrough
	default:
		fs, err := sqlitefs.NewCursor(store.connection)
		if err != nil {
			return nil, nil, err
		}
		store.Fs = fs
	}

	if create {
		err = store.setPragma("application_id", applicationID)
		if err != nil {
			return nil, nil, err
		}

		err = store.setPragma("user_version", Version)
		if err != nil {
			return nil, nil, err
		}

		err = store.exec("CREATE TABLE \"elements\" (" +
			"\"id\" TEXT NOT NULL," +
			"\"json\" TEXT," +
			"\"insert_time\" TEXT," +
			"PRIMARY KEY(\"id\")" +
			")")
		if err != nil {
			return nil, nil, err
		}
		err = store.exec("CREATE INDEX type_index ON elements(json_extract(json, '$.type'));")
		if err != nil {
			return nil, nil, err
		}
		err = store.exec("CREATE INDEX origin_path_index ON elements(json_extract(json, '$.origin.path'));")
		if err != nil {
			return nil, nil, err
		}
		err = store.exec("CREATE INDEX path_index ON elements(json_extract(json, '$.path'));")
		if err != nil {
			return nil, nil, err
		}
		err = store.exec("CREATE INDEX key_index ON elements(json_extract(json, '$.key'));")
		if err != nil {
			return nil, nil, err
		}
		err = store.exec("CREATE INDEX errors_index ON elements(json_extract(json, '$.errors'));")
		if err != nil {
			return nil, nil, err
		}
		err = store.exec("CREATE INDEX label_index ON elements(json_extract(json, '$.labels'));")
		if err != nil {
			return nil, nil, err
		}
		err = store.exec("CREATE INDEX artifact_index ON elements(json_extract(json, '$.artifact'));")
		if err != nil {
			return nil, nil, err
		}
	} else {
		applicationID, err := store.pragma("application_id")
		if err != nil {
			return nil, nil, err
		}
		if applicationID != elementaryApplicationID && applicationID != elementaryApplicationIDDirFS {
			msg := "wrong file format (application_id is %d)"
			return nil, nil, fmt.Errorf(msg, applicationID)
		}

		version, err := store.pragma("user_version")
		if err != nil {
			return nil, nil, err
		}
		if version != 3 && version != 2 {
			msg := "wrong file format (user_version is %d, requires 2 or 3)"
			return nil, nil, fmt.Errorf(msg, version)
		}
	}

	store.types = newTypeMap()
	err = store.setupTypes()
	if err != nil {
		return nil, nil, err
	}

	setupSchemaValidation()

	return store, store.Close, nil
}

func (store *ForensicStore) SetFS(fs afero.Fs) {
	store.Fs = fs
}

func (store *ForensicStore) Connection() *sqlite.Conn {
	return store.connection
}

/* ################################
#   API
################################ */

// Insert adds a single element.
func (store *ForensicStore) Insert(element JSONElement) (string, error) {
	// validate element
	valErr, err := validateSchema(element)
	if err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}
	if len(valErr) > 0 {
		return "", fmt.Errorf("element could not be validated [%s]", strings.Join(valErr, ","))
	}

	// unmarshal element
	nestedElement := map[string]interface{}{}
	err = json.Unmarshal(element, &nestedElement)
	if err != nil {
		return "", err
	}

	elementType, ok := nestedElement["type"]
	if !ok {
		return "", errors.New("element requires type")
	}
	if _, ok := nestedElement[elementType.(string)]; ok {
		return "", fmt.Errorf("element must not contain a field '%s'", elementType)
	}
	id, ok := nestedElement["id"]
	if !ok {
		id = elementType.(string) + "--" + uuid.New().String()
		nestedElement["id"] = id

		element, err = json.Marshal(nestedElement)
		if err != nil {
			return "", err
		}
	}

	store.types.addAll(elementType.(string), nestedElement)

	// insert into elements table
	query := fmt.Sprintf("INSERT INTO `elements` (id, json, insert_time) VALUES ($id, $json, $time)") // #nosec
	stmt, err := store.connection.Prepare(query)
	if err != nil {
		return "", fmt.Errorf("could not prepare statement %s: %w", query, err)
	}
	stmt.SetText("$id", id.(string))
	stmt.SetText("$json", string(element))
	stmt.SetText("$time", time.Now().UTC().Format(time.RFC3339Nano))
	_, err = stmt.Step()
	if err != nil {
		return "", fmt.Errorf("could not exec statement %s: %w", query, err)
	}

	return id.(string), nil
}

// InsertBatch adds a set of elements. All elements must have the same fields.
func (store *ForensicStore) InsertBatch(elements []JSONElement) ([]string, error) { // nolint:gocyclo,funlen
	if len(elements) == 0 {
		return nil, nil
	}
	var ids []string
	for _, element := range elements {
		id, err := store.Insert(element)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// InsertStruct converts a Go struct to a map and inserts it.
func (store *ForensicStore) InsertStruct(element interface{}) (string, error) {
	ids, err := store.InsertStructBatch([]interface{}{element})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// InsertStructBatch adds a list of structs to the forensicstore.
func (store *ForensicStore) InsertStructBatch(elements []interface{}) ([]string, error) {
	var ms []JSONElement
	for _, element := range elements {
		m := structs.Map(element)
		m = lower(m).(map[string]interface{})
		b, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		ms = append(ms, b)
	}

	return store.InsertBatch(ms)
}

// Get retreives a single element.
func (store *ForensicStore) Get(id string) (element JSONElement, err error) {
	stmt, err := store.connection.Prepare(fmt.Sprintf("SELECT json FROM `elements` WHERE id=?")) // #nosec
	if err != nil {
		return nil, err
	}

	stmt.BindText(1, id)

	elements, err := store.rowsToElements(stmt)
	if err != nil {
		return nil, err
	}
	if len(elements) > 0 {
		return elements[0], nil
	}
	return nil, errors.New("element does not exist")
}

// Query executes a sql query.
func (store *ForensicStore) Query(query string) (elements []JSONElement, err error) {
	stmt, err := store.connection.Prepare(query)
	if err != nil {
		return nil, err
	}

	return store.rowsToElements(stmt)
}

// StoreFile adds a file to the database folder.
func (store *ForensicStore) StoreFile(filePath string) (storePath string, file io.WriteCloser, teardown func() error, err error) {
	err = store.Fs.MkdirAll(filepath.Dir(filePath), 0755)
	if err != nil {
		return "", nil, nil, err
	}

	i := 0
	ext := filepath.Ext(filePath)
	remoteStoreFilePath := filePath
	base := remoteStoreFilePath[:len(remoteStoreFilePath)-len(ext)]

	exists, err := afero.Exists(store.Fs, remoteStoreFilePath)
	if err != nil {
		return "", nil, nil, err
	}
	for exists {
		remoteStoreFilePath = fmt.Sprintf("%s_%d%s", base, i, ext)
		i++
		exists, err = afero.Exists(store.Fs, remoteStoreFilePath)
		if err != nil {
			return "", nil, nil, err
		}
	}

	file, err = store.Fs.Create(remoteStoreFilePath)
	return remoteStoreFilePath, file, file.Close, err
}

// LoadFile opens a file from the database folder.
func (store *ForensicStore) LoadFile(filePath string) (file io.ReadCloser, teardown func() error, err error) {
	file, err = store.Fs.Open(filePath)
	return file, file.Close, err
}

// Close saves and closes the database.
func (store *ForensicStore) Close() error {
	if store.types.changed {
		_ = store.createViews()
	}

	return store.connection.Close()
}

func (store *ForensicStore) createViews() error {
	for typeName, fields := range store.types.all() {
		err := store.exec(fmt.Sprintf("DROP VIEW IF EXISTS '%s'", typeName))
		if err != nil {
			return err
		}
		var columns []string
		for field := range fields {
			columns = append(columns, fmt.Sprintf("json_extract(json, '$.%s') as '%s'", field, field))
		}
		sort.Strings(columns)
		query := fmt.Sprintf(
			"CREATE VIEW '%s' AS SELECT %s FROM elements WHERE json_extract(json, '$.%s') = '%s'",
			typeName, strings.Join(columns, ", "), discriminator, typeName,
		) // #nosec

		err = store.exec(query) // #nosec
		if err != nil {
			return err
		}
	}
	return nil
}

/* ################################
#   Validate
################################ */

// Validate checks the database for various flaws.
func (store *ForensicStore) Validate() (flaws []string, err error) {
	flaws = []string{}
	expectedFiles := map[string]bool{}

	elements, err := store.All()
	if err != nil {
		return nil, err
	}
	for _, element := range elements {
		validationErrors, elementExpectedFiles, err := store.validateElement(element)
		if err != nil {
			return nil, err
		}
		flaws = append(flaws, validationErrors...)
		for _, elementExpectedFile := range elementExpectedFiles {
			expectedFiles[filepath.ToSlash(elementExpectedFile)] = true
		}
	}

	foundFiles := map[string]bool{}
	var additionalFiles []string
	err = afero.Walk(store.Fs, "/", func(path string, info os.FileInfo, err error) error {
		path = filepath.ToSlash(path)
		if info == nil || info.IsDir() {
			return nil
		}

		foundFiles[path] = true
		if _, ok := expectedFiles[path]; !ok {
			additionalFiles = append(additionalFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(additionalFiles) > 0 {
		flaws = append(flaws, fmt.Sprintf("additional files: ('%s')", strings.Join(additionalFiles, "', '")))
	}

	var missingFiles []string
	for expectedFile := range expectedFiles {
		if _, ok := foundFiles[expectedFile]; !ok {
			missingFiles = append(missingFiles, expectedFile)
		}
	}

	if len(missingFiles) > 0 {
		flaws = append(flaws, fmt.Sprintf("missing files: ('%s')", strings.Join(missingFiles, "', '")))
	}
	return flaws, nil
}

func (store *ForensicStore) validateElement(element JSONElement) (flaws []string, elementExpectedFiles []string, err error) { // nolint:gocyclo,funlen,gocognit
	flaws = []string{}
	elementExpectedFiles = []string{}

	elementType := gjson.GetBytes(element, discriminator)
	if !elementType.Exists() {
		flaws = append(flaws, "element needs to have a type")
	}

	valErr, err := validateSchema(element)
	if err != nil {
		return nil, nil, err
	}
	flaws = append(flaws, valErr...)

	var fields map[string]interface{}
	err = json.Unmarshal(element, &fields)
	if err != nil {
		return nil, nil, err
	}

	for field := range fields {
		if strings.HasSuffix(field, "_path") {
			exportPath := fields[field].(string)

			if strings.Contains(exportPath, "..") {
				flaws = append(flaws, fmt.Sprintf("'..' in %s", exportPath))
				continue
			}

			elementExpectedFiles = append(elementExpectedFiles, "/"+exportPath)

			exits, err := afero.Exists(store.Fs, exportPath)
			if err != nil {
				return nil, nil, err
			}
			if !exits {
				continue
			}

			if size, ok := fields["size"]; ok {
				fi, err := store.Fs.Stat(exportPath)
				if err != nil {
					return nil, nil, err
				}
				if int64(size.(float64)) != fi.Size() {
					flaws = append(flaws, fmt.Sprintf("wrong size for %s (is %d, expected %d)", exportPath, fi.Size(), int64(size.(float64))))
				}
			}

			if hashes, ok := fields["hashes"]; ok {
				for algorithm, value := range hashes.(map[string]interface{}) {
					var h hash.Hash
					switch algorithm {
					case "MD5":
						h = md5.New() // #nosec
					case "SHA1":
						h = sha1.New() // #nosec
					case "SHA-1":
						h = sha1.New() // #nosec
					case "SHA-256":
						h = sha256.New()
					default:
						flaws = append(flaws, fmt.Sprintf("unsupported hash %s for %s", algorithm, exportPath))
						continue
					}

					f, err := store.Fs.Open(exportPath)
					if err != nil {
						return nil, nil, err
					}

					_, err = io.Copy(h, f)
					f.Close() // nolint:errcheck
					if err != nil {
						return nil, nil, err
					}

					if fmt.Sprintf("%x", h.Sum(nil)) != value {
						flaws = append(flaws, fmt.Sprintf("hashvalue mismatch %s for %s", algorithm, exportPath))
					}
				}
			}
		}
	}

	return flaws, elementExpectedFiles, nil
}

// Select retrieves all elements of a discriminated attribute.
func (store *ForensicStore) Select(conditions []map[string]string) (elements []JSONElement, err error) {
	var ors []string
	for _, condition := range conditions {
		var ands []string
		for key, value := range condition {
			ands = append(ands, fmt.Sprintf("json_extract(json, '$.%s') LIKE '%s'", key, value))
		}
		if len(ands) > 0 {
			ors = append(ors, "("+strings.Join(ands, " AND ")+")")
		}
	}

	query := "SELECT json FROM \"elements\""
	if len(ors) > 0 {
		query += fmt.Sprintf(" WHERE %s", strings.Join(ors, " OR ")) // #nosec
	}

	stmt, err := store.connection.Prepare(query) // #nosec
	if err != nil {
		return nil, err
	}

	return store.rowsToElements(stmt)
}

// Search for elements.
func (store *ForensicStore) Search(q string) (elements []JSONElement, err error) {
	stmt, err := store.connection.Prepare("SELECT json FROM elements WHERE json LIKE $query")
	if err != nil {
		return nil, err
	}
	stmt.SetText("$query", "%"+q+"%")
	return store.rowsToElements(stmt)
}

// All returns every element.
func (store *ForensicStore) All() (elements []JSONElement, err error) {
	return store.Select(nil)
}

/* ################################
#   Intern
################################ */

func (store *ForensicStore) rowsToElements(stmt *sqlite.Stmt) (elements []JSONElement, err error) {
	elements = []JSONElement{}
	for {
		if hasRow, err := stmt.Step(); err != nil {
			return nil, err
		} else if !hasRow {
			break
		}
		elements = append(elements, JSONElement(stmt.GetText("json")))
	}
	return elements, stmt.Finalize()
}

func isElementTable(name string) bool {
	if strings.HasPrefix(name, "sqlite") || strings.HasPrefix(name, "_") {
		return false
	}
	if name == "sqlar" {
		return false
	}
	if name == "elements" {
		return false
	}

	for _, suffix := range []string{"_data", "_idx", "_content", "_docsize", "_config"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	return true
}

func (store *ForensicStore) setupTypes() error {
	stmt, err := store.connection.Prepare("SELECT name FROM sqlite_master")
	if err != nil {
		return err
	}

	for {
		if hasRow, err := stmt.Step(); err != nil {
			return err
		} else if !hasRow {
			break
		}

		name := stmt.GetText("name")

		if !isElementTable(name) {
			continue
		}

		pragmaStmt, err := store.connection.Prepare(fmt.Sprintf("PRAGMA table_info (\"%s\")", name))
		if err != nil {
			return err
		}

		for {
			if pragmaHasRow, err := pragmaStmt.Step(); err != nil {
				return err
			} else if !pragmaHasRow {
				break
			}

			columnName := pragmaStmt.GetText("name")
			store.types.add(name, columnName)
		}
		err = pragmaStmt.Finalize()
		if err != nil {
			return err
		}
	}

	return stmt.Finalize()
}

func (store *ForensicStore) exec(query string) error {
	stmt, err := store.connection.Prepare(query)
	if err != nil {
		return err
	}

	_, err = stmt.Step()
	if err != nil {
		return err
	}

	return stmt.Finalize()
}
