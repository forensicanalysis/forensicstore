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

// Package forensicstore can create,
// access and process forensic artifacts bundled in so called forensicstores
// (a database for forensic artifacts).
package forensicstore

import (
	"crypto/md5"  // #nosec
	"crypto/sha1" // #nosec
	"encoding/json"
	"fmt"
	"github.com/tidwall/gjson"
	"hash"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"crawshaw.io/sqlite"
	"github.com/fatih/structs"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/qri-io/jsonschema"
	"github.com/spf13/afero"

	"github.com/forensicanalysis/forensicstore/goflatten"
	"github.com/forensicanalysis/forensicstore/sqlitefs"
	"github.com/forensicanalysis/stixgo"
)

const forensicstoreVersion = 2
const elementaryApplicationID = 1701602669
const discriminator = "type"

// The ForensicStore is a central storage for elements in digital forensic
// investigations. It stores any piece of information in the investigation and
// serves as a single source of truth for the data. Cases, artifacts, evidence,
// meta data, bookmarks etc. can be stored in the forensicstore. Larger binary
// objects like files are usually stored outside the forensicstore and references
// from the forensicstore.
type ForensicStore struct {
	fs          afero.Fs
	cursor      *sqlite.Conn
	types       *typeMap
	schemas     *schemaMap
	columnMutex sync.Mutex
}

var ErrStoreExists = fmt.Errorf("store already exists")
var ErrStoreNotExists = fmt.Errorf("store does not exist")

// New creates a new Forensicstore.
func New(url string) (*ForensicStore, error) { // nolint:gocyclo
	return open(url, true)
}

// Open opens an existing Forensicstore.
func Open(url string) (*ForensicStore, error) { // nolint:gocyclo
	return open(url, false)
}

func pragma(conn *sqlite.Conn, name string) (int64, error) {
	stmt, err := conn.Prepare("PRAGMA " + name)
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

func setPragma(conn *sqlite.Conn, name string, i int64) error {
	stmt, err := conn.Prepare("PRAGMA " + name + " = " + fmt.Sprint(i))
	if err != nil {
		return err
	}
	_, err = stmt.Step()
	if err != nil {
		return err
	}
	return stmt.Finalize()
}

func open(url string, create bool) (*ForensicStore, error) { // nolint:gocyclo,funlen,gocognit

	if url != ":memory:" {
		url = strings.TrimRight(url, "/")

		exists := true
		_, err := os.Stat(url)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			exists = false
		}

		if create && exists {
			return nil, ErrStoreExists
		}
		if !create && !exists {
			return nil, ErrStoreNotExists
		}

		if create {
			err = os.MkdirAll(path.Dir(url), 0750)
			if err != nil {
				return nil, err
			}

			log.Printf("Creating store %s", url)
			_, err := os.Create(url)
			if err != nil {
				return nil, err
			}
		}
	}

	store := &ForensicStore{}

	var err error
	store.cursor, err = sqlite.OpenConn(url, 0)
	if err != nil {
		return nil, err
	}

	fs, err := sqlitefs.NewCursor(store.cursor)
	if err != nil {
		return nil, err
	}
	store.fs = fs

	if create {
		err = setPragma(store.cursor, "application_id", elementaryApplicationID)
		if err != nil {
			return nil, err
		}

		err = setPragma(store.cursor, "user_version", forensicstoreVersion)
		if err != nil {
			return nil, err
		}

		err = store.exec("CREATE VIRTUAL TABLE `elements` " +
			"USING fts5(id UNINDEXED, json, insert_time UNINDEXED, tokenize=\"unicode61 tokenchars '/.'\")")
		if err != nil {
			return nil, err
		}
	} else {
		applicationID, err := pragma(store.cursor, "application_id")
		if err != nil {
			return nil, err
		}
		if applicationID != elementaryApplicationID {
			msg := "wrong file format (application_id is %d, requires %d)"
			return nil, fmt.Errorf(msg, applicationID, elementaryApplicationID)
		}

		version, err := pragma(store.cursor, "user_version")
		if err != nil {
			return nil, err
		}
		if version != forensicstoreVersion {
			msg := "wrong file format (user_version is %d, requires %d)"
			return nil, fmt.Errorf(msg, version, forensicstoreVersion)
		}
	}

	store.types = newTypeMap()
	err = store.setupTypes()
	if err != nil {
		return nil, err
	}

	store.schemas = newSchemaMap()
	nameTitle := map[string]string{}
	// unmarshal schemas
	for name, content := range stixgo.FS {
		schema := &jsonschema.RootSchema{}
		if err := json.Unmarshal(content, schema); err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("unmarshal error %s", name))
		}

		nameTitle[path.Base(name)] = schema.Title

		err = store.SetSchema(schema.Title, schema)
		if err != nil {
			return nil, err
		}
	}

	// replace refs
	for _, schema := range store.Schemas() {
		err = walkJSON(schema, func(elem jsonschema.JSONPather) error {
			if sch, ok := elem.(*jsonschema.Schema); ok {
				if sch.Ref != "" && sch.Ref[0] != '#' {
					sch.Ref = "elementary:" + nameTitle[path.Base(sch.Ref)]
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		jsonschema.DefaultSchemaPool["elementary:"+schema.Title] = &schema.Schema
	}

	// fetch references
	for _, schema := range store.Schemas() {
		err = schema.FetchRemoteReferences()
		if err != nil {
			return nil, errors.Wrap(err, "could not FetchRemoteReferences")
		}
	}

	return store, nil
}

func (store *ForensicStore) SetFS(fs afero.Fs) {
	store.fs = fs
}

/* ################################
#   API
################################ */

// Insert adds a single element.
func (store *ForensicStore) Insert(element JSONElement) (string, error) {
	// validate element
	valErr, err := store.validateElementSchema(element)
	if err != nil {
		return "", errors.Wrap(err, "validation failed")
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

	// flatten element
	flatElement, err := goflatten.Flatten(nestedElement)
	if err != nil {
		return "", errors.Wrap(err, "could not flatten element")
	}

	elementType, ok := flatElement["type"]
	if !ok {
		return "", errors.New("element requires type")
	}
	if _, ok := flatElement[elementType.(string)]; ok {
		return "", fmt.Errorf("element must not contain a field '%s'", elementType)
	}
	id, ok := flatElement["id"]
	if !ok {
		id = elementType.(string) + "--" + uuid.New().String()
		flatElement["id"] = id

		element, err = json.Marshal(nestedElement)
		if err != nil {
			return "", err
		}
	}

	store.types.addAll(elementType.(string), flatElement)

	// insert into elements table
	query := fmt.Sprintf("INSERT INTO `elements` (id, json, insert_time) VALUES ($id, $json, $time)") // #nosec
	stmt, err := store.cursor.Prepare(query)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("could not prepare statement %s", query))
	}
	stmt.SetText("$id", id.(string))
	stmt.SetText("$json", string(element))
	stmt.SetText("$time", time.Now().Format("2006-01-02T15:04:05.000Z"))
	_, err = stmt.Step()
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprint("could not exec statement", query))
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
	stmt, err := store.cursor.Prepare(fmt.Sprintf("SELECT json FROM `elements` WHERE id=?")) // #nosec
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
	stmt, err := store.cursor.Prepare(query)
	if err != nil {
		return nil, err
	}

	return store.rowsToElements(stmt)
}

// StoreFile adds a file to the database folder.
func (store *ForensicStore) StoreFile(filePath string) (storePath string, file io.WriteCloser, err error) {
	err = store.fs.MkdirAll(filepath.Dir(filePath), 0755)
	if err != nil {
		return "", nil, err
	}

	i := 0
	ext := filepath.Ext(filePath)
	remoteStoreFilePath := filePath
	base := remoteStoreFilePath[:len(remoteStoreFilePath)-len(ext)]

	exists, err := afero.Exists(store.fs, remoteStoreFilePath)
	if err != nil {
		return "", nil, err
	}
	for exists {
		remoteStoreFilePath = fmt.Sprintf("%s_%d%s", base, i, ext)
		i++
		exists, err = afero.Exists(store.fs, remoteStoreFilePath)
		if err != nil {
			return "", nil, err
		}
	}

	file, err = store.fs.Create(remoteStoreFilePath)
	return remoteStoreFilePath, file, err
}

// LoadFile opens a file from the database folder.
func (store *ForensicStore) LoadFile(filePath string) (file io.ReadCloser, err error) {
	return store.fs.Open(filePath)
}

// Close saves and closes the database.
func (store *ForensicStore) Close() error {
	if store.types.changed {
		_ = store.createViews()
	}

	return store.cursor.Close()
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
		err = store.exec(
			fmt.Sprintf("CREATE VIEW '%s' AS SELECT %s FROM elements WHERE json_extract(json, '$.%s') = '%s'",
				typeName, strings.Join(columns, ", "), discriminator, typeName),
		)
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
	err = afero.Walk(store.fs, "/", func(path string, info os.FileInfo, err error) error {
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

	valErr, err := store.validateElementSchema(element)
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

			exits, err := afero.Exists(store.fs, exportPath)
			if err != nil {
				return nil, nil, err
			}
			if !exits {
				continue
			}

			if size, ok := fields["size"]; ok {
				fi, err := store.fs.Stat(exportPath)
				if err != nil {
					return nil, nil, err
				}
				if int64(size.(float64)) != fi.Size() {
					flaws = append(flaws, fmt.Sprintf("wrong size for %s (is %d, expected %d)", exportPath, fi.Size(), size))
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
					default:
						flaws = append(flaws, fmt.Sprintf("unsupported hash %s for %s", algorithm, exportPath))
						continue
					}

					f, err := store.fs.Open(exportPath)
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

func (store *ForensicStore) validateElementSchema(element JSONElement) (flaws []string, err error) {
	elementType := gjson.GetBytes(element, discriminator)
	if !elementType.Exists() {
		flaws = append(flaws, "element needs to have a type")
	}

	rootSchema, err := store.Schema(elementType.String())
	if err != nil {
		if err == errSchemaNotFound {
			return nil, nil // no schema for element
		}
		return nil, errors.Wrap(err, "could not get schema")
	}

	errs, err := rootSchema.ValidateBytes(element)
	if err != nil {
		return nil, err
	}
	for _, verr := range errs {
		flaws = append(flaws, fmt.Sprintf("failed to validate element: %s", verr))
	}
	return flaws, nil
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

	stmt, err := store.cursor.Prepare(query) // #nosec
	if err != nil {
		return nil, err
	}

	return store.rowsToElements(stmt)
}

// Search for elements
func (store *ForensicStore) Search(q string) (elements []JSONElement, err error) {
	stmt, err := store.cursor.Prepare("SELECT json FROM elements WHERE elements = $query")
	if err != nil {
		return nil, err
	}
	stmt.SetText("$query", q)
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
	stmt, err := store.cursor.Prepare("SELECT name FROM sqlite_master")
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

		pragmaStmt, err := store.cursor.Prepare(fmt.Sprintf("PRAGMA table_info (\"%s\")", name))
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
	stmt, err := store.cursor.Prepare(query)
	if err != nil {
		return err
	}

	_, err = stmt.Step()
	if err != nil {
		return err
	}

	return stmt.Finalize()
}

// SetSchema inserts or replaces a json schema for input validation.
func (store *ForensicStore) SetSchema(id string, schema *jsonschema.RootSchema) error {
	if val, ok := store.schemas.load(id); ok && val == schema {
		return nil
	}

	// store.schemas[id] = schema
	store.schemas.store(id, schema)
	return nil
}

var errSchemaNotFound = errors.New("schema not found")

// Schema gets a single schema from the database.
func (store *ForensicStore) Schema(id string) (*jsonschema.RootSchema, error) {
	if schema, ok := store.schemas.load(id); ok {
		return schema, nil
	}

	return nil, errSchemaNotFound
}

// Schemas gets all schemas from the database.
func (store *ForensicStore) Schemas() []*jsonschema.RootSchema {
	return store.schemas.values()
}
