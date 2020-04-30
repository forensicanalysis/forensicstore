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
	"database/sql"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/structs"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3" // Import sqlite3 driver
	"github.com/pkg/errors"
	"github.com/qri-io/jsonschema"
	"github.com/spf13/afero"

	"github.com/forensicanalysis/forensicstore/goflatten"
	"github.com/forensicanalysis/stixgo"
)

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
	NewDB       bool
	storeFolder string
	cursor      *sql.DB
	sqlMutex    sync.RWMutex
	fileMutex   sync.RWMutex
	tables      *tableMap
	schemas     *schemaMap
}

var ErrStoreExists = fmt.Errorf("store already exists: %w", os.ErrExist)
var ErrStoreNotExists = fmt.Errorf("store does not exist: %w", os.ErrNotExist)

// New creates a new Forensicstore.
func New(url string) (*ForensicStore, error) { // nolint:gocyclo
	return open(url, true)
}

// Open opens an existing Forensicstore.
func Open(url string) (*ForensicStore, error) { // nolint:gocyclo
	return open(url, false)
}

func open(url string, create bool) (*ForensicStore, error) { // nolint:gocyclo
	url = strings.TrimRight(url, "/")

	db := &ForensicStore{
		Fs:          afero.NewOsFs(),
		storeFolder: url,
	}

	dbFile := filepath.Join(url, "element.db")
	exists, err := afero.Exists(db, dbFile)
	if err != nil {
		return nil, err
	}
	if create && exists {
		return nil, ErrStoreExists
	}
	if !create && !exists {
		return nil, ErrStoreNotExists
	}

	if create {
		err = db.MkdirAll(db.storeFolder, 0755)
		if err != nil {
			return nil, err
		}

		log.Printf("Creating store %s", db.storeFolder)
		_, err := db.Create(dbFile)
		if err != nil {
			return nil, err
		}
	}

	db.cursor, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}

	db.schemas = newSchemaMap()

	db.tables = newTableMap()

	tables, err := db.getTables()
	if err != nil {
		return nil, err
	}
	for tableName, table := range tables {
		db.tables.store(tableName, table)
	}

	nameTitle := map[string]string{}

	// unmarshal schemas
	for name, content := range stixgo.FS {
		schema := &jsonschema.RootSchema{}
		if err := json.Unmarshal(content, schema); err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("unmarshal error %s", name))
		}

		nameTitle[path.Base(name)] = schema.Title

		err = db.SetSchema(schema.Title, schema)
		if err != nil {
			return nil, err
		}
	}

	// replace refs
	for _, schema := range db.Schemas() {
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
	for _, schema := range db.Schemas() {
		err = schema.FetchRemoteReferences()
		if err != nil {
			return nil, errors.Wrap(err, "could not FetchRemoteReferences")
		}
	}

	return db, nil
}

/* ################################
#   API
################################ */

// Insert adds a single element.
func (db *ForensicStore) Insert(elem Element) (string, error) {
	ids, err := db.InsertBatch([]Element{elem})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// InsertBatch adds a set of elements. All elements must have the same fields.
func (db *ForensicStore) InsertBatch(elements []Element) ([]string, error) { // nolint:gocyclo
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

	valErr, err := db.validateElementSchema(firstElement)
	if err != nil {
		return nil, errors.Wrap(err, "validation failed")
	}
	if len(valErr) > 0 {
		return nil, fmt.Errorf("element could not be validated [%s]", strings.Join(valErr, ","))
	}
	if err := db.ensureTable(flatElement, firstElement); err != nil {
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
		valErr, err := db.validateElementSchema(element)
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
	stmt, err := db.cursor.Prepare(query)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("could not prepare statement %s", query))
	}

	db.sqlMutex.Lock()
	defer db.sqlMutex.Unlock()
	_, err = stmt.Exec(columnValues...)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("could not exec statement", query, columnValues))
	}

	return ids, nil
}

// InsertStruct converts a Go struct to a map and inserts it.
func (db *ForensicStore) InsertStruct(element interface{}) (string, error) {
	ids, err := db.InsertStructBatch([]interface{}{element})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// InsertStructBatch adds a list of structs to the forensicstore.
func (db *ForensicStore) InsertStructBatch(elements []interface{}) ([]string, error) {
	var ms []Element
	for _, element := range elements {
		m := structs.Map(element)
		m = lower(m).(map[string]interface{})
		ms = append(ms, m)
	}

	return db.InsertBatch(ms)
}

// Get retreives a single element.
func (db *ForensicStore) Get(id string) (element Element, err error) {
	parts := strings.Split(id, "--")
	discriminator := parts[0]

	stmt, err := db.cursor.Prepare(fmt.Sprintf("SELECT * FROM \"%s\" WHERE id=?", discriminator)) // #nosec
	if err != nil {
		return nil, err
	}

	db.sqlMutex.RLock()
	rows, err := stmt.Query(id)
	db.sqlMutex.RUnlock()
	if err != nil {
		return nil, err
	}

	elements, err := db.rowsToElements(rows)
	if err != nil {
		return nil, err
	}
	if len(elements) > 0 {
		return elements[0], nil
	}
	return nil, errors.New("element does not exist")
}

// Query executes a sql query.
func (db *ForensicStore) Query(query string) (elements []Element, err error) {
	stmt, err := db.cursor.Prepare(query)
	if err != nil {
		return nil, err
	}

	db.sqlMutex.RLock()
	rows, err := stmt.Query()
	db.sqlMutex.RUnlock()
	if err != nil {
		return nil, err
	}

	return db.rowsToElements(rows)
}

// StoreFile adds a file to the database folder.
func (db *ForensicStore) StoreFile(filePath string) (storePath string, file afero.File, err error) {
	err = db.MkdirAll(filepath.Join(db.storeFolder, filepath.Dir(filePath)), 0755)
	if err != nil {
		return "", nil, err
	}

	db.fileMutex.Lock()
	i := 0
	ext := filepath.Ext(filePath)
	remoteStoreFilePath := path.Join(db.storeFolder, filePath)
	base := remoteStoreFilePath[:len(remoteStoreFilePath)-len(ext)]

	exists, err := afero.Exists(db, remoteStoreFilePath)
	if err != nil {
		db.fileMutex.Unlock()
		return "", nil, err
	}
	for exists {
		remoteStoreFilePath = fmt.Sprintf("%s_%d%s", base, i, ext)
		i++
		exists, err = afero.Exists(db, remoteStoreFilePath)
		if err != nil {
			db.fileMutex.Unlock()
			return "", nil, err
		}
	}

	file, err = db.Create(remoteStoreFilePath)
	db.fileMutex.Unlock()
	return remoteStoreFilePath[len(db.storeFolder)+1:], file, err
}

// LoadFile opens a file from the database folder.
func (db *ForensicStore) LoadFile(filePath string) (file afero.File, err error) {
	return db.Open(path.Join(db.storeFolder, filePath))
}

// Close saves and closes the database.
func (db *ForensicStore) Close() error {
	return db.cursor.Close()
}

/* ################################
#   Validate
################################ */

// Validate checks the database for various flaws.
func (db *ForensicStore) Validate() (flaws []string, err error) {
	flaws = []string{}
	expectedFiles := map[string]bool{}
	expectedFiles[filepath.FromSlash("/element.db")] = true
	// expectedFiles["/element.db-journal"] = true

	elements, err := db.All()
	if err != nil {
		return nil, err
	}
	for _, element := range elements {
		validationErrors, elementExpectedFiles, err := db.validateElement(element)
		if err != nil {
			return nil, err
		}
		flaws = append(flaws, validationErrors...)
		for _, elementExpectedFile := range elementExpectedFiles {
			expectedFiles[filepath.FromSlash(elementExpectedFile)] = true
		}
	}

	foundFiles := map[string]bool{}
	var additionalFiles []string
	err = afero.Walk(db, db.storeFolder, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, "/element.db-journal") || info.IsDir() {
			return nil
		}
		path = path[len(db.storeFolder):]

		foundFiles[path] = true
		if _, ok := expectedFiles[path]; !ok {
			additionalFiles = append(additionalFiles, filepath.ToSlash(path))
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
			missingFiles = append(missingFiles, filepath.ToSlash(expectedFile))
		}
	}

	if len(missingFiles) > 0 {
		flaws = append(flaws, fmt.Sprintf("missing files: ('%s')", strings.Join(missingFiles, "', '")))
	}
	return flaws, nil
}

func (db *ForensicStore) validateElement(element Element) (flaws []string, elementExpectedFiles []string, err error) { // nolint:gocyclo
	flaws = []string{}
	elementExpectedFiles = []string{}

	if _, ok := element[discriminator]; !ok {
		flaws = append(flaws, "element needs to have a discriminator")
	}

	valErr, err := db.validateElementSchema(element)
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

			exits, err := afero.Exists(db, filepath.Join(db.storeFolder, exportPath))
			if err != nil {
				return nil, nil, err
			}
			if !exits {
				continue
			}

			if size, ok := element["size"]; ok {
				fi, err := db.Stat(filepath.Join(db.storeFolder, exportPath))
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

					f, err := db.Open(filepath.Join(db.storeFolder, exportPath))
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

func (db *ForensicStore) validateElementSchema(element Element) (flaws []string, err error) {
	rootSchema, err := db.Schema(element[discriminator].(string))
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

		flaws = append(flaws, errors.Wrap(err, "failed to validate element"+id).Error())
	}
	return flaws, nil
}

// Select retrieves all elements of a discriminated attribute.
func (db *ForensicStore) Select(elementType string, conditions []map[string]string) (elements []Element, err error) {
	var ors []string
	for _, condition := range conditions {
		var ands []string
		for key, value := range condition {
			if key != "type" {
				ands = append(ands, fmt.Sprintf("\"%s\" LIKE \"%s\"", key, value))
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

	stmt, err := db.cursor.Prepare(query) // #nosec
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, err
	}

	db.sqlMutex.RLock()
	rows, err := stmt.Query()
	db.sqlMutex.RUnlock()
	if err != nil {
		return nil, err
	}

	return db.rowsToElements(rows)
}

// All returns every element.
func (db *ForensicStore) All() (elements []Element, err error) {
	elements = []Element{}

	stmt, err := db.cursor.Prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '%sqlite%';")
	if err != nil {
		return nil, err
	}

	db.sqlMutex.RLock()
	rows, err := stmt.Query()
	db.sqlMutex.RUnlock()
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		s := ""
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if strings.HasPrefix(s, "_") {
			continue
		}
		selectElements, err := db.Select(s, nil)
		if err != nil {
			return nil, err
		}
		elements = append(elements, selectElements...)
	}
	return
}

/* ################################
#   Intern
################################ */
func (db *ForensicStore) rowsToElements(rows *sql.Rows) (elements []Element, err error) {
	defer rows.Close() //good habit to closes
	cols, _ := rows.Columns()

	elements = []Element{}

	for rows.Next() {
		// Create a slice of interface{}'s to represent each column,
		// and a second slice to contain pointers to each element in the columns slice.
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		// Scan the result into the column pointers...
		if err := rows.Scan(columnPointers...); err != nil {
			return nil, err
		}

		// Create our map, and retrieve the value for each column from the pointers slice,
		// storing it in the map with the name of the column as the key.
		m := make(map[string]interface{})
		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
			types, _ := rows.ColumnTypes()
			if (*val) == nil {
				continue
			}

			switch types[i].ScanType().Kind() {
			case reflect.Int:
				m[colName] = float64((*val).(int))
			case reflect.Int64:
				m[colName] = float64((*val).(int64))
			case reflect.String:

				switch v := (*val).(type) {
				case string:
					m[colName] = v
				case []uint8:
					m[colName] = string(v)
				default:
					return nil, errors.New("unknown type")
				}

			default:
				m[colName] = *val
			}
		}

		element, _ := goflatten.Unflatten(m)
		elements = append(elements, element)
	}
	return elements, nil
}

type columnInfo struct {
	cid       int
	name      string
	ctype     string
	notnull   bool
	dfltValue interface{}
	pk        int
}

func (db *ForensicStore) getTables() (map[string]map[string]string, error) {
	db.sqlMutex.RLock()
	rows, err := db.cursor.Query("SELECT name FROM sqlite_master")
	db.sqlMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tables := map[string]map[string]string{}

	for rows.Next() {
		name := ""
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}

		if strings.HasPrefix(name, "sqlite") || strings.HasPrefix(name, "_") {
			continue
		}
		tables[name] = map[string]string{}

		db.sqlMutex.RLock()
		columnRows, err := db.cursor.Query(fmt.Sprintf("PRAGMA table_info (\"%s\")", name))
		db.sqlMutex.RUnlock()
		if err != nil {
			return nil, err
		}

		for columnRows.Next() {
			var c columnInfo
			if err := columnRows.Scan(&c.cid, &c.name, &c.ctype, &c.notnull, &c.dfltValue, &c.pk); err != nil {
				columnRows.Close()
				return nil, err
			}
			tables[name][c.name] = c.ctype
		}
		columnRows.Close()
	}
	return tables, nil
}

func (db *ForensicStore) ensureTable(flatElement Element, element Element) error {
	elementType := element[discriminator].(string)

	db.sqlMutex.Lock()
	defer db.sqlMutex.Unlock()

	if table, ok := db.tables.load(elementType); !ok {
		if err := db.createTable(flatElement); err != nil {
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
			if err := db.addMissingColumns(element[discriminator].(string), flatElement, missingColumns); err != nil {
				return errors.Wrap(err, fmt.Sprintf("adding missing column failed %v", missingColumns))
			}
		}
	}
	return nil
}

func (db *ForensicStore) createTable(flatElement Element) error {
	table := map[string]string{"id": "TEXT", discriminator: "TEXT"}
	db.tables.store(flatElement[discriminator].(string), table)

	columns := []string{"id TEXT PRIMARY KEY", discriminator + " TEXT NOT NULL"}
	for columnName := range flatElement {
		if columnName != "id" && columnName != discriminator {
			sqlDataType := getSQLDataType(flatElement[columnName])
			db.tables.innerstore(flatElement[discriminator].(string), columnName, sqlDataType)
			columns = append(columns, fmt.Sprintf("`%s` %s", columnName, sqlDataType))
		}
	}
	columnText := strings.Join(columns, ", ")

	_, err := db.cursor.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s` (%s)", flatElement[discriminator], columnText))
	return err
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

func (db *ForensicStore) addMissingColumns(table string, columns map[string]interface{}, newColumns []string) error {
	sort.Strings(newColumns)
	for _, newColumn := range newColumns {
		sqlDataType := getSQLDataType(columns[newColumn])
		db.tables.innerstore(table, newColumn, sqlDataType)
		_, err := db.cursor.Exec(fmt.Sprintf("ALTER TABLE \"%s\" ADD COLUMN \"%s\" %s", table, newColumn, sqlDataType))
		if err != nil {
			return err
		}
	}
	return nil
}

// SetSchema inserts or replaces a json schema for input validation.
func (db *ForensicStore) SetSchema(id string, schema *jsonschema.RootSchema) error {
	if val, ok := db.schemas.load(id); ok && val == schema {
		return nil
	}

	// db.schemas[id] = schema
	db.schemas.store(id, schema)
	return nil
}

var errSchemaNotFound = errors.New("schema not found")

// Schema gets a single schema from the database.
func (db *ForensicStore) Schema(id string) (*jsonschema.RootSchema, error) {
	if schema, ok := db.schemas.load(id); ok {
		return schema, nil
	}

	return nil, errSchemaNotFound
}

// Schemas gets all schemas from the database.
func (db *ForensicStore) Schemas() []*jsonschema.RootSchema {
	return db.schemas.values()
}
