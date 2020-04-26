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

// Package gojsonlite provides concurrency safe functions to access the jsonlite
// format (flattened json objects in a sqlite data-base).
package gojsonlite

import (
	"crypto/md5"  // #nosec
	"crypto/sha1" // #nosec
	"database/sql"
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

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3" // Import sqlite3 driver
	"github.com/pkg/errors"
	"github.com/qri-io/jsonschema"
	"github.com/spf13/afero"

	"github.com/forensicanalysis/forensicstore/goflatten"
	"github.com/forensicanalysis/forensicstore/gostore"
)

// Item is a storeable element.
type Item = gostore.Item

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

// JSONLite is a file based strorage for json data.
type JSONLite struct {
	afero.Fs
	NewDB       bool
	url         string
	storeFolder string
	dbFile      string
	cursor      *sql.DB
	sqlMutex    sync.RWMutex
	fileMutex   sync.RWMutex
	tables      *tableMap
	schemas     *schemaMap
}

// New creates or opens a JSONLite database.
func New(url string) (*JSONLite, error) { // nolint:gocyclo
	db := &JSONLite{}
	if url[len(url)-1:] == "/" {
		url = url[:len(url)-1]
	}
	db.url = url

	db.Fs = afero.NewOsFs()
	db.storeFolder = url
	db.dbFile = filepath.Join(db.storeFolder, "item.db")

	exists, err := afero.Exists(db, db.dbFile)
	if err != nil {
		return nil, err
	}
	db.NewDB = !exists

	err = db.MkdirAll(db.storeFolder, 0755)
	if err != nil {
		return nil, err
	}

	if db.NewDB {
		log.Printf("Creating store %s", db.storeFolder)
		_, err := db.Create(db.dbFile)
		if err != nil {
			return nil, err
		}
	}

	db.cursor, err = sql.Open("sqlite3", db.dbFile)
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

	return db, nil
}

/* ################################
#   API
################################ */

// Insert adds a single item.
func (db *JSONLite) Insert(item Item) (string, error) {
	uids, err := db.InsertBatch([]Item{item})
	if err != nil {
		return "", err
	}
	return uids[0], nil
}

// InsertBatch adds a set of items. All items must have the same fields.
func (db *JSONLite) InsertBatch(items []Item) ([]string, error) { // nolint:gocyclo,funlen
	if len(items) == 0 {
		return nil, nil
	}
	firstItem := items[0]

	if _, ok := firstItem[discriminator]; !ok {
		return nil, errors.New("missing discriminator in item")
	}

	// map id => uid
	if uid, ok := firstItem["id"]; ok && uid != "" {
		firstItem["id"] = fmt.Sprint(uid)
	} else if uid, ok := firstItem["uid"]; ok && uid != "" {
		firstItem["id"] = fmt.Sprint(uid)
	} else {
		firstItem["id"] = firstItem[discriminator].(string) + "--" + uuid.New().String()
	}

	flatItem, err := goflatten.Flatten(firstItem)
	if err != nil {
		return nil, errors.Wrap(err, "could not flatten item")
	}

	valErr, err := db.validateItemSchema(flatItem)
	if err != nil {
		return nil, errors.Wrap(err, "validation failed")
	}
	if len(valErr) > 0 {
		return nil, fmt.Errorf("first item could not be validated [%s]", strings.Join(valErr, ","))
	}

	flatItem["uid"] = flatItem["id"]
	delete(flatItem, "id")

	if err := db.ensureTable(flatItem, firstItem); err != nil {
		return nil, errors.Wrap(err, "could not ensure table")
	}

	// get columnNames
	var columnNames []string
	for k := range flatItem {
		columnNames = append(columnNames, k)
	}

	// get columnValues
	var placeholderGrp []string
	var columnValues []interface{}
	var uids []string
	for _, item := range items {
		// map id => uid
		if uid, ok := item["id"]; ok {
			item["id"] = fmt.Sprint(uid)
		} else if uid, ok := item["uid"]; ok {
			item["id"] = fmt.Sprint(uid)
		} else {
			item["id"] = item[discriminator].(string) + "--" + uuid.New().String()
		}

		flatItem, err := goflatten.Flatten(item)
		if err != nil {
			return nil, errors.Wrap(err, "could not flatten item")
		}

		valErr, err := db.validateItemSchema(flatItem)
		if err != nil {
			return nil, errors.Wrap(err, "validation failed")
		}
		if len(valErr) > 0 {
			return nil, fmt.Errorf("item could not be validated [%s]", strings.Join(valErr, ","))
		}

		flatItem["uid"] = flatItem["id"]
		delete(flatItem, "id")

		for _, name := range columnNames {
			columnValues = append(columnValues, flatItem[name])
		}
		placeholderGrp = append(placeholderGrp, "("+strings.Repeat("?,", len(flatItem)-1)+"?)")

		uids = append(uids, flatItem["uid"].(string))
	}

	query := fmt.Sprintf(
		"INSERT INTO \"%s\"(%s) VALUES %s",
		firstItem[discriminator].(string),
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

	return uids, nil
}

// Get retreives a single item.
func (db *JSONLite) Get(id string) (item Item, err error) {
	parts := strings.Split(id, "--")
	discriminator := parts[0]

	stmt, err := db.cursor.Prepare(fmt.Sprintf("SELECT * FROM \"%s\" WHERE uid=?", discriminator)) // #nosec
	if err != nil {
		return nil, err
	}

	db.sqlMutex.RLock()
	rows, err := stmt.Query(id)
	db.sqlMutex.RUnlock()
	if err != nil {
		return nil, err
	}

	items, err := db.rowsToItems(rows)
	if err != nil {
		return nil, err
	}
	if len(items) > 0 {
		return items[0], nil
	}
	return nil, errors.New("item does not exist")
}

// Query executes a sql query.
func (db *JSONLite) Query(query string) (items []Item, err error) {
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

	return db.rowsToItems(rows)
}

// Update adds new keys to an item.
func (db *JSONLite) Update(id string, partialItem Item) (string, error) {
	return "", errors.New("not yet implemented")
}

// StoreFile adds a file to the database folder.
func (db *JSONLite) StoreFile(filePath string) (storePath string, file afero.File, err error) {
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
func (db *JSONLite) LoadFile(filePath string) (file afero.File, err error) {
	return db.Open(path.Join(db.storeFolder, filePath))
}

// Close saves and closes the database.
func (db *JSONLite) Close() error {
	return db.cursor.Close()
}

/* ################################
#   Validate
################################ */

// Validate checks the database for various flaws.
func (db *JSONLite) Validate() (flaws []string, err error) {
	flaws = []string{}
	expectedFiles := map[string]bool{}
	expectedFiles[filepath.FromSlash("/item.db")] = true
	// expectedFiles["/item.db-journal"] = true

	items, err := db.All()
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		validationErrors, itemExpectedFiles, err := db.validateItem(item)
		if err != nil {
			return nil, err
		}
		flaws = append(flaws, validationErrors...)
		for _, itemExpectedFile := range itemExpectedFiles {
			expectedFiles[filepath.FromSlash(itemExpectedFile)] = true
		}
	}

	foundFiles := map[string]bool{}
	var additionalFiles []string
	err = afero.Walk(db, db.storeFolder, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, "/item.db-journal") || info.IsDir() {
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

func (db *JSONLite) validateItem(item Item) (flaws []string, itemExpectedFiles []string, err error) { // nolint:gocyclo,gocognit,funlen,lll
	flaws = []string{}
	itemExpectedFiles = []string{}

	if _, ok := item[discriminator]; !ok {
		flaws = append(flaws, "item needs to have a discriminator")
	}

	valErr, err := db.validateItemSchema(item)
	if err != nil {
		return nil, nil, err
	}
	flaws = append(flaws, valErr...)

	for field := range item {
		if strings.HasSuffix(field, "_path") {
			pathFlaws, pathItemExpectedFiles, err := db.handlePathField(item, field)
			if err != nil {
				return nil, nil, err
			}
			flaws = append(flaws, pathFlaws...)
			itemExpectedFiles = append(itemExpectedFiles, pathItemExpectedFiles...)
		}
	}

	return flaws, itemExpectedFiles, nil
}

func (db *JSONLite) handlePathField(item Item, field string) (flaws, itemExpectedFiles []string, err error) { //nolint:gocyclo,lll
	exportPath := item[field].(string)

	if strings.Contains(exportPath, "..") {
		flaws = append(flaws, fmt.Sprintf("'..' in %s", exportPath))
		return flaws, itemExpectedFiles, nil
	}

	itemExpectedFiles = append(itemExpectedFiles, "/"+exportPath)

	exits, err := afero.Exists(db, filepath.Join(db.storeFolder, exportPath))
	if err != nil {
		return nil, nil, err
	}
	if !exits {
		return flaws, itemExpectedFiles, nil
	}

	if size, ok := item["size"]; ok {
		fi, err := db.Stat(filepath.Join(db.storeFolder, exportPath))
		if err != nil {
			return nil, nil, err
		}
		if int64(size.(float64)) != fi.Size() {
			flaws = append(flaws, fmt.Sprintf("wrong size for %s (is %d, expected %d)", exportPath, fi.Size(), size))
		}
	}

	if hashes, ok := item["hashes"]; ok {
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
				return flaws, itemExpectedFiles, nil
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
	return flaws, itemExpectedFiles, nil
}

func (db *JSONLite) validateItemSchema(item Item) (flaws []string, err error) {
	rootSchema, err := db.Schema(item[discriminator].(string))
	if err != nil {
		if err == errSchemaNotFound {
			return nil, nil // no schema for item
		}
		return nil, errors.Wrap(err, "could not get schema")
	}

	var i map[string]interface{} = item
	var errs []jsonschema.ValError
	rootSchema.Validate("/", i, &errs)
	for _, err := range errs {
		id := ""
		if uid, ok := item["uid"]; ok {
			id = " " + uid.(string)
		}

		flaws = append(flaws, errors.Wrap(err, "failed to validate item"+id).Error())
	}
	return flaws, nil
}

// Select retrieves all items of a discriminated attribute.
func (db *JSONLite) Select(itemType string, conditions []map[string]string) (items []Item, err error) {
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

	query := fmt.Sprintf("SELECT * FROM \"%s\"", itemType) // #nosec
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

	return db.rowsToItems(rows)
}

// All returns every item.
func (db *JSONLite) All() (items []Item, err error) {
	items = []Item{}

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
		selectItems, err := db.Select(s, nil)
		if err != nil {
			return nil, err
		}
		items = append(items, selectItems...)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return items, nil
}

/* ################################
#   Intern
################################ */

func (db *JSONLite) rowsToItems(rows *sql.Rows) (items []Item, err error) {
	defer rows.Close() //good habit to closes
	cols, _ := rows.Columns()

	items = []Item{}

	for rows.Next() {
		// Create a slice of interface{}'s to represent each column,
		// and a second slice to contain pointers to each item in the columns slice.
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

		// map uid => id
		if uid, ok := m["uid"]; ok {
			m["id"] = uid
			delete(m, "uid")
		}

		item, _ := goflatten.Unflatten(m)
		items = append(items, item)
	}
	return items, nil
}

type columnInfo struct {
	cid       int
	name      string
	ctype     string
	notnull   bool
	dfltValue interface{}
	pk        int
}

func (db *JSONLite) getTables() (map[string]map[string]string, error) {
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
		if columnRows.Err() != nil {
			return nil, rows.Err()
		}
		columnRows.Close()
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return tables, nil
}

func (db *JSONLite) ensureTable(flatItem Item, item Item) error {
	itemType := item[discriminator].(string)

	db.sqlMutex.Lock()
	defer db.sqlMutex.Unlock()

	if table, ok := db.tables.load(itemType); !ok { //nolint:nestif
		if err := db.createTable(flatItem); err != nil {
			return errors.Wrap(err, "create table failed")
		}
	} else {
		var missingColumns []string
		for attribute := range flatItem {
			if _, ok := table[attribute]; !ok {
				missingColumns = append(missingColumns, attribute)
			}
		}

		if len(missingColumns) > 0 {
			if err := db.addMissingColumns(item[discriminator].(string), flatItem, missingColumns); err != nil {
				return errors.Wrap(err, fmt.Sprintf("adding missing column failed %v", missingColumns))
			}
		}
	}
	return nil
}

func (db *JSONLite) createTable(flatItem Item) error {
	table := map[string]string{"uid": "TEXT", discriminator: "TEXT"}
	db.tables.store(flatItem[discriminator].(string), table)

	columns := []string{"uid TEXT PRIMARY KEY", discriminator + " TEXT NOT NULL"}
	for columnName := range flatItem {
		if columnName != "uid" && columnName != discriminator {
			sqlDataType := getSQLDataType(flatItem[columnName])
			db.tables.innerstore(flatItem[discriminator].(string), columnName, sqlDataType)
			columns = append(columns, fmt.Sprintf("`%s` %s", columnName, sqlDataType))
		}
	}
	columnText := strings.Join(columns, ", ")

	_, err := db.cursor.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s` (%s)", flatItem[discriminator], columnText))
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

func (db *JSONLite) addMissingColumns(table string, columns map[string]interface{}, newColumns []string) error {
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
func (db *JSONLite) SetSchema(id string, schema *jsonschema.RootSchema) error {
	if val, ok := db.schemas.load(id); ok && val == schema {
		return nil
	}

	// db.schemas[id] = schema
	db.schemas.store(id, schema)
	return nil
}

var errSchemaNotFound = errors.New("schema not found")

// Schema gets a single schema from the database.
func (db *JSONLite) Schema(id string) (*jsonschema.RootSchema, error) {
	if schema, ok := db.schemas.load(id); ok {
		return schema, nil
	}

	return nil, errSchemaNotFound
}

// Schemas gets all schemas from the database.
func (db *JSONLite) Schemas() []*jsonschema.RootSchema {
	return db.schemas.values()
}
