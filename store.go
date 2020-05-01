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
	"crypto/md5"  // #nosec
	"crypto/sha1" // #nosec
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
	"sync"

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

const (
	// integer represents the SQL INTEGER type
	integer = "INTEGER"
	// numeric represents the SQL NUMERIC type
	numeric = "NUMERIC"
	// text represents the SQL TEXT type
	text = "TEXT"
	// blob represents the SQL BLOB type
	// blob = "BLOB"
)

const discriminator = "type"

// The ForensicStore is a central storage for elements in digital forensic
// investigations. It stores any piece of information in the investigation and
// serves as a single source of truth for the data. Cases, artifacts, evidence,
// meta data, bookmarks etc. can be stored in the forensicstore. Larger binary
// objects like files are usually stored outside the forensicstore and references
// from the forensicstore.
type ForensicStore struct {
	afero.Fs
	cursor      *sqlite.Conn
	tables      *tableMap
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

func open(url string, create bool) (*ForensicStore, error) { // nolint:gocyclo
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

	store := &ForensicStore{}

	if create {
		err = os.MkdirAll(path.Dir(url), 0755)
		if err != nil {
			return nil, err
		}

		log.Printf("Creating store %s", url)
		_, err := os.Create(url)
		if err != nil {
			return nil, err
		}
	}

	fs, err := sqlitefs.New(url)
	if err != nil {
		return nil, err
	}
	store.Fs = fs

	store.cursor, err = sqlite.OpenConn(url, 0)
	if err != nil {
		return nil, err
	}

	if create {
		err = setPragma(store.cursor, "application_id", elementaryApplicationID)
		if err != nil {
			return nil, err
		}

		err = setPragma(store.cursor, "user_version", forensicstoreVersion)
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

	store.schemas = newSchemaMap()

	store.tables = newTableMap()

	tables, err := store.getTables()
	if err != nil {
		return nil, err
	}
	for tableName, table := range tables {
		store.tables.store(tableName, table)
	}

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
					sch.Ref = "jsonlite:" + nameTitle[path.Base(sch.Ref)]
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		jsonschema.DefaultSchemaPool["jsonlite:"+schema.Title] = &schema.Schema
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

/* ################################
#   API
################################ */

// Insert adds a single element.
func (store *ForensicStore) Insert(elem Element) (string, error) {
	ids, err := store.InsertBatch([]Element{elem})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// InsertBatch adds a set of elements. All elements must have the same fields.
func (store *ForensicStore) InsertBatch(elements []Element) ([]string, error) { // nolint:gocyclo
	if len(elements) == 0 {
		return nil, nil
	}
	firstElement := elements[0]

	if _, ok := firstElement[discriminator]; !ok {
		return nil, errors.New("missing discriminator in element")
	}

	if _, ok := firstElement["id"]; !ok {
		firstElement["id"] = firstElement[discriminator].(string) + "--" + uuid.New().String()
	}

	flatElement, err := goflatten.Flatten(firstElement)
	if err != nil {
		return nil, errors.Wrap(err, "could not flatten element")
	}

	valErr, err := store.validateElementSchema(firstElement)
	if err != nil {
		return nil, errors.Wrap(err, "validation failed")
	}
	if len(valErr) > 0 {
		return nil, fmt.Errorf("element could not be validated [%s]", strings.Join(valErr, ","))
	}
	if err := store.ensureTable(flatElement, firstElement); err != nil {
		return nil, errors.Wrap(err, "could not ensure table")
	}

	// get columnNames
	var columnNames []string
	for k := range flatElement {
		columnNames = append(columnNames, k)
	}

	// get columnValues
	var placeholderGrp []string
	var columnValues []interface{}
	var ids []string
	for _, element := range elements {
		valErr, err := store.validateElementSchema(element)
		if err != nil {
			return nil, errors.Wrap(err, "validation failed")
		}
		if len(valErr) > 0 {
			return nil, fmt.Errorf("element could not be validated [%s]", strings.Join(valErr, ","))
		}

		flatElement, err := goflatten.Flatten(element)
		if err != nil {
			return nil, errors.Wrap(err, "could not flatten element")
		}

		if _, ok := flatElement["id"]; !ok {
			flatElement["id"] = flatElement[discriminator].(string) + "--" + uuid.New().String()
		}

		for _, name := range columnNames {
			columnValues = append(columnValues, flatElement[name])
		}
		placeholderGrp = append(placeholderGrp, "("+strings.Repeat("?,", len(flatElement)-1)+"?)")

		ids = append(ids, flatElement["id"].(string))
	}

	query := fmt.Sprintf(
		"INSERT INTO \"%s\"(%s) VALUES %s",
		firstElement[discriminator].(string),
		`"`+strings.Join(columnNames, `","`)+`"`,
		strings.Join(placeholderGrp, ","),
	) // #nosec
	stmt, err := store.cursor.Prepare(query)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("could not prepare statement %s", query))
	}

	i := sqlite.BindIncrementor()
	for _, columnValue := range columnValues {
		stmt.BindText(i(), fmt.Sprint(columnValue))
	}

	_, err = stmt.Step()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("could not exec statement", query, columnValues))
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
	var ms []Element
	for _, element := range elements {
		m := structs.Map(element)
		m = lower(m).(map[string]interface{})
		ms = append(ms, m)
	}

	return store.InsertBatch(ms)
}

// Get retreives a single element.
func (store *ForensicStore) Get(id string) (element Element, err error) {
	parts := strings.Split(id, "--")
	discriminator := parts[0]

	stmt, err := store.cursor.Prepare(fmt.Sprintf("SELECT * FROM \"%s\" WHERE id=?", discriminator)) // #nosec
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
func (store *ForensicStore) Query(query string) (elements []Element, err error) {
	stmt, err := store.cursor.Prepare(query)
	if err != nil {
		return nil, err
	}

	return store.rowsToElements(stmt)
}

// StoreFile adds a file to the database folder.
func (store *ForensicStore) StoreFile(filePath string) (storePath string, file afero.File, err error) {
	err = store.MkdirAll(filepath.Dir(filePath), 0755)
	if err != nil {
		return "", nil, err
	}

	i := 0
	ext := filepath.Ext(filePath)
	remoteStoreFilePath := filePath
	base := remoteStoreFilePath[:len(remoteStoreFilePath)-len(ext)]

	exists, err := afero.Exists(store, remoteStoreFilePath)
	if err != nil {
		return "", nil, err
	}
	for exists {
		remoteStoreFilePath = fmt.Sprintf("%s_%d%s", base, i, ext)
		i++
		exists, err = afero.Exists(store, remoteStoreFilePath)
		if err != nil {
			return "", nil, err
		}
	}

	file, err = store.Create(remoteStoreFilePath)
	return remoteStoreFilePath, file, err
}

// LoadFile opens a file from the database folder.
func (store *ForensicStore) LoadFile(filePath string) (file afero.File, err error) {
	return store.Open(filePath)
}

// Close saves and closes the database.
func (store *ForensicStore) Close() error {
	if closer, ok := store.Fs.(io.Closer); ok {
		_ = closer.Close()
	}
	return store.cursor.Close()
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
	err = afero.Walk(store, "/", func(path string, info os.FileInfo, err error) error {
		path = filepath.ToSlash(path)
		if info.IsDir() {
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

func (store *ForensicStore) validateElement(element Element) (flaws []string, elementExpectedFiles []string, err error) { // nolint:gocyclo
	flaws = []string{}
	elementExpectedFiles = []string{}

	if _, ok := element[discriminator]; !ok {
		flaws = append(flaws, "element needs to have a discriminator")
	}

	valErr, err := store.validateElementSchema(element)
	if err != nil {
		return nil, nil, err
	}
	flaws = append(flaws, valErr...)

	for field := range element {
		if strings.HasSuffix(field, "_path") {
			exportPath := element[field].(string)

			if strings.Contains(exportPath, "..") {
				flaws = append(flaws, fmt.Sprintf("'..' in %s", exportPath))
				continue
			}

			elementExpectedFiles = append(elementExpectedFiles, "/"+exportPath)

			exits, err := afero.Exists(store, exportPath)
			if err != nil {
				return nil, nil, err
			}
			if !exits {
				continue
			}

			if size, ok := element["size"]; ok {
				fi, err := store.Stat(exportPath)
				if err != nil {
					return nil, nil, err
				}
				if int64(size.(float64)) != fi.Size() {
					flaws = append(flaws, fmt.Sprintf("wrong size for %s (is %d, expected %d)", exportPath, fi.Size(), size))
				}
			}

			if hashes, ok := element["hashes"]; ok {
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

					f, err := store.Open(exportPath)
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

func (store *ForensicStore) validateElementSchema(element Element) (flaws []string, err error) {
	rootSchema, err := store.Schema(element[discriminator].(string))
	if err != nil {
		if err == errSchemaNotFound {
			return nil, nil // no schema for element
		}
		return nil, errors.Wrap(err, "could not get schema")
	}

	var errs []jsonschema.ValError
	var i map[string]interface{} = element
	rootSchema.Validate("/", i, &errs)
	for _, err := range errs {
		id := ""
		if id, ok := element["id"]; ok {
			id = " " + id.(string)
		}

		flaws = append(flaws, errors.Wrap(err, "failed to validate element"+id+" "+fmt.Sprintf("%#v", i)).Error())
	}
	return flaws, nil
}

// Select retrieves all elements of a discriminated attribute.
func (store *ForensicStore) Select(elementType string, conditions []map[string]string) (elements []Element, err error) {
	var ors []string
	for _, condition := range conditions {
		var ands []string
		for key, value := range condition {
			if key != "type" {
				ands = append(ands, fmt.Sprintf("\"%s\" LIKE '%s'", key, value))
			}
		}
		if len(ands) > 0 {
			ors = append(ors, "("+strings.Join(ands, " AND ")+")")
		}
	}

	query := fmt.Sprintf("SELECT * FROM \"%s\"", elementType) // #nosec
	if len(ors) > 0 {
		query += fmt.Sprintf(" WHERE %s", strings.Join(ors, " OR ")) // #nosec
	}

	stmt, err := store.cursor.Prepare(query) // #nosec
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, err
	}

	/*/
	i := sqlite.BindIncrementor()
	for _, value := range values {
		stmt.BindText(i(), value)
	}
	/*/
	return store.rowsToElements(stmt)
}

// All returns every element.
func (store *ForensicStore) All() (elements []Element, err error) {
	elements = []Element{}

	stmt, err := store.cursor.Prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '%sqlite%' AND name != 'sqlar'")
	if err != nil {
		return nil, err
	}

	for {
		if hasRow, err := stmt.Step(); err != nil {
			return nil, err
		} else if !hasRow {
			break
		}

		s := stmt.GetText("name")
		if strings.HasPrefix(s, "_") {
			continue
		}
		selectElements, err := store.Select(s, nil)
		if err != nil {
			return nil, err
		}
		elements = append(elements, selectElements...)
	}
	return elements, stmt.Finalize()
}

/* ################################
#   Intern
################################ */
func (store *ForensicStore) rowsToElements(stmt *sqlite.Stmt) (elements []Element, err error) {
	colCount := stmt.ColumnCount()

	elements = []Element{}

	for {
		// Create a slice of interface{}'s to represent each column,
		// and a second slice to contain pointers to each element in the columns slice.
		columns := make([]interface{}, colCount)
		columnPointers := make([]interface{}, colCount)
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if hasRow, err := stmt.Step(); err != nil {
			return nil, err
		} else if !hasRow {
			break
		}

		flatItem := make(map[string]interface{})

		for i := 0; i < colCount; i++ {
			name := stmt.ColumnName(i)
			switch stmt.ColumnType(i) {
			case sqlite.SQLITE_INTEGER:
				flatItem[name] = float64(stmt.GetInt64(name))
			case sqlite.SQLITE_FLOAT:
				flatItem[name] = stmt.GetFloat(name)
			case sqlite.SQLITE_TEXT:
				flatItem[name] = stmt.GetText(name)
			case sqlite.SQLITE_BLOB:
			}
		}

		element, _ := goflatten.Unflatten(flatItem)
		elements = append(elements, element)
	}
	return elements, stmt.Finalize()
}

func (store *ForensicStore) getTables() (map[string]map[string]string, error) {
	stmt, err := store.cursor.Prepare("SELECT name FROM sqlite_master")
	if err != nil {
		return nil, err
	}

	tables := map[string]map[string]string{}

	for {
		if hasRow, err := stmt.Step(); err != nil {
			return nil, err
		} else if !hasRow {
			break
		}

		name := stmt.GetText("name")

		if strings.HasPrefix(name, "sqlite") || strings.HasPrefix(name, "_") {
			continue
		}
		if name == "sqlar" {
			continue
		}
		tables[name] = map[string]string{}

		pragmaStmt, err := store.cursor.Prepare(fmt.Sprintf("PRAGMA table_info (\"%s\")", name))
		if err != nil {
			return nil, err
		}

		for {
			if pragmaHasRow, err := pragmaStmt.Step(); err != nil {
				return nil, err
			} else if !pragmaHasRow {
				break
			}

			columnName := pragmaStmt.GetText("name")
			columnType := pragmaStmt.GetText("type")
			tables[name][columnName] = columnType
		}
		pragmaStmt.Finalize()
	}

	return tables, stmt.Finalize()
}

func (store *ForensicStore) ensureTable(flatElement Element, element Element) error {
	elementType := element[discriminator].(string)

	store.columnMutex.Lock()
	defer store.columnMutex.Unlock()
	if table, ok := store.tables.load(elementType); !ok {
		if err := store.createTable(flatElement); err != nil {
			return errors.Wrap(err, "create table failed")
		}
	} else {
		var missingColumns []string
		for attribute := range flatElement {
			if _, ok := table[attribute]; !ok {
				missingColumns = append(missingColumns, attribute)
			}
		}

		if len(missingColumns) > 0 {
			if err := store.addMissingColumns(element[discriminator].(string), flatElement, missingColumns); err != nil {
				return errors.Wrap(err, fmt.Sprintf("adding missing column failed %v", missingColumns))
			}
		}
	}
	return nil
}

func (store *ForensicStore) createTable(flatElement Element) error {
	table := map[string]string{"id": "TEXT", discriminator: "TEXT"}
	store.tables.store(flatElement[discriminator].(string), table)

	columns := []string{"id TEXT PRIMARY KEY", discriminator + " TEXT NOT NULL"}
	for columnName := range flatElement {
		if columnName != "id" && columnName != discriminator {
			sqlDataType := getSQLDataType(flatElement[columnName])
			store.tables.innerstore(flatElement[discriminator].(string), columnName, sqlDataType)
			columns = append(columns, fmt.Sprintf("`%s` %s", columnName, sqlDataType))
		}
	}
	columnText := strings.Join(columns, ", ")

	return store.exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s` (%s)", flatElement[discriminator], columnText))
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

func getSQLDataType(value interface{}) string {
	switch value.(type) {
	case int, int16, int8, int32, int64, uint, uint16, uint8, uint32, uint64:
		return integer
	case float32, float64:
		return numeric
	default:
		return text
	}
}

func (store *ForensicStore) addMissingColumns(table string, columns map[string]interface{}, newColumns []string) error {
	sort.Strings(newColumns)
	for _, newColumn := range newColumns {
		sqlDataType := getSQLDataType(columns[newColumn])
		store.tables.innerstore(table, newColumn, sqlDataType)
		err := store.exec(fmt.Sprintf("ALTER TABLE \"%s\" ADD COLUMN \"%s\" %s", table, newColumn, sqlDataType))
		if err != nil {
			return err
		}
	}
	return nil
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
