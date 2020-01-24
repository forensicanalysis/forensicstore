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
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/forensicanalysis/forensicstore/goflatten"
	"github.com/forensicanalysis/forensicstore/gostore"
	"github.com/forensicanalysis/fslib/aferotools/copy"
	"github.com/google/uuid"
	"github.com/imdario/mergo"
	_ "github.com/mattn/go-sqlite3" // Import sqlite3 driver
	"github.com/pkg/errors"
	"github.com/qri-io/jsonschema"
	"github.com/spf13/afero"
)

// Item is a storeable element.
type Item = gostore.Item

const (
	// INTEGER represents the SQL INTEGER type
	INTEGER = "INTEGER"
	// NUMERIC represents the SQL NUMERIC type
	NUMERIC = "NUMERIC"
	// TEXT represents the SQL TEXT type
	TEXT = "TEXT"
	// BLOB represents the SQL BLOB type
	// BLOB = "BLOB"
)

// JSONLite is a file based strorage for json data.
type JSONLite struct {
	afero.Fs
	NewDB             bool
	remoteIsLocal     bool
	remoteURL         string
	remoteStoreFolder string
	remoteDBFile      string
	localFS           afero.Fs
	localStoreFolder  string
	localDBFile       string
	cursor            *sql.DB
	sqlMutex          sync.RWMutex
	fileMutex         sync.RWMutex
	tables            *tableMap  // map[string]map[string]string
	options           sync.Map   // map[string]interface{}
	schemas           *schemaMap // map[string]*jsonschema.RootSchema
}

func toFS(url string) (fs afero.Fs, path string, isLocal bool) {
	// TODO: use path lib?
	// fs = afero.NewBasePathFs(afero.NewOsFs(), filepath.Directory(url))
	// return fs, filepath.Base(url), true
	// bpfs.RealPath(...)
	return afero.NewOsFs(), url, true
}

// New creates or opens a JSONLite database.
func New(remoteURL string, discriminator string) (*JSONLite, error) {
	db := &JSONLite{}
	if remoteURL[len(remoteURL)-1:] == "/" {
		remoteURL = remoteURL[:len(remoteURL)-1]
	}
	db.remoteURL = remoteURL

	db.Fs, db.remoteStoreFolder, db.remoteIsLocal = toFS(remoteURL)
	db.remoteDBFile = filepath.Join(db.remoteStoreFolder, "item.db")

	db.localFS, db.localStoreFolder = db.Fs, db.remoteStoreFolder
	if !db.remoteIsLocal {
		tmpDir, err := ioutil.TempDir("", "jsonlite")
		if err != nil {
			return nil, err
		}
		localPath := filepath.Join(tmpDir, filepath.Base(remoteURL))
		db.localFS, db.localStoreFolder, _ = toFS(localPath)
	}
	db.localDBFile = filepath.Join(db.localStoreFolder, "item.db")

	exists, err := afero.Exists(db, db.remoteDBFile)
	if err != nil {
		return nil, err
	}
	db.NewDB = !exists

	err = db.localFS.MkdirAll(db.localStoreFolder, 0755)
	if err != nil {
		return nil, err
	}

	if db.NewDB {
		log.Println("Store does not exist", db.remoteDBFile)
		_, err := db.Create(db.remoteDBFile)
		if err != nil {
			return nil, err
		}
	} else if !db.remoteIsLocal {
		log.Println("Store exists", db, db.remoteStoreFolder)
		if err := copy.File(db, db.localFS, db.remoteDBFile, db.localDBFile); err != nil {
			return nil, err
		}
	}

	db.cursor, err = sql.Open("sqlite3", db.localDBFile)
	if err != nil {
		return nil, err
	}

	// db.options = map[string]interface{}{}
	// db.schemas = map[string]*jsonschema.RootSchema{}
	db.schemas = newSchemaMap()

	if db.NewDB {
		err = db.createOptionsTable()
		if err != nil {
			return nil, err
		}
		db.SetStrict(true)
		db.SetDiscriminator(discriminator)
	}

	err = db.loadSchemas()
	if err != nil {
		return nil, err
	}

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
	return uids[0], err
}

// InsertBatch adds a set of items. All items must have the same fields.
func (db *JSONLite) InsertBatch(items []Item) ([]string, error) {
	if len(items) == 0 {
		return nil, nil
	}
	firstItem := items[0]

	if _, ok := firstItem[db.Discriminator()]; !ok {
		return nil, errors.New("missing discriminator in item")
	}

	if _, ok := firstItem["uid"]; !ok {
		firstItem["uid"] = firstItem[db.Discriminator()].(string) + "--" + uuid.New().String()
	}

	flatItem, err := goflatten.Flatten(firstItem)
	if err != nil {
		return nil, errors.Wrap(err, "could not flatten item")
	}

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
		if db.Strict() {
			valErr, err := db.validateItemSchema(item)
			if err != nil {
				return nil, errors.Wrap(err, "validation failed")
			}
			if len(valErr) > 0 {
				return nil, fmt.Errorf("item could not be validated [%s]", strings.Join(valErr, ","))
			}
		}

		flatItem, err := goflatten.Flatten(item)
		if err != nil {
			return nil, errors.Wrap(err, "could not flatten item")
		}
		if _, ok := flatItem["uid"]; !ok {
			flatItem["uid"] = flatItem[db.Discriminator()].(string) + "--" + uuid.New().String()
		}
		for _, name := range columnNames {
			columnValues = append(columnValues, flatItem[name])
		}
		placeholderGrp = append(placeholderGrp, "("+strings.Repeat("?,", len(flatItem)-1)+"?)")

		uids = append(uids, flatItem["uid"].(string))
	}

	query := fmt.Sprintf(
		"INSERT INTO \"%s\"(%s) VALUES %s",
		firstItem[db.Discriminator()].(string),
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
	/*
		updatedItem, err := db.Get(id)
		if err != nil {
			return "", err
		}
		oldDiscriminator := updatedItem[db.Discriminator()].(string)
		if err := mergo.Merge(&updatedItem, partialItem); err != nil {
			return "", err
		}

		parts := strings.Split(id, "--")
		itemUUID := parts[1]

		if val, ok := partialItem[db.Discriminator()]; ok && oldDiscriminator != partialItem[db.Discriminator()].(string) {
			updatedItem["uid"] = val.(string) + "--" + itemUUID

			stmt, err := db.cursor.Prepare(fmt.Sprintf("DELETE FROM %s WHERE uid=?", oldDiscriminator)) // #nosec
			if err != nil {
				return "", err
			}

			_, err = stmt.Exec(id)
			if err != nil {
				return "", err
			}
			return db.Insert(updatedItem)
		}

		flatItem, err := goflatten.Flatten(updatedItem)
		if err != nil {
			return "", err
		}

		err = db.ensureTable(flatItem, updatedItem)
		if err != nil {
			return "", err
		}

		values := []interface{}{}
		replacements := []string{}
		for k, v := range flatItem {
			replacements = append(replacements, fmt.Sprintf("\"%s\"=?", k))
			values = append(values, v)
		}
		replace := strings.Join(replacements, ", ")

		values = append(values, id)
		table := updatedItem[db.Discriminator()]
		stmt, err := db.cursor.Prepare(fmt.Sprintf("UPDATE %s SET %s WHERE uid=?", table, replace)) // #nosec
		if err != nil {
			return "", err
		}

		_, err = stmt.Exec(values)
		if err != nil {
			return "", err
		}

		return updatedItem["uid"].(string), nil
	*/
}

// ImportJSONLite merges another JSONLite into this one.
func (db *JSONLite) ImportJSONLite(url string) (err error) {
	// TODO: import items with "_path" on sublevel"…
	// TODO: import does not need to unflatten and flatten

	importStore, err := New(url, "")
	if err != nil {
		return err
	}
	items, err := importStore.All()
	if err != nil {
		return err
	}
	for _, item := range items {
		for field := range item {
			item := item
			if strings.HasSuffix(field, "_path") {
				dstPath, writer, err := db.StoreFile(item[field].(string))
				if err != nil {
					return err
				}
				reader, err := importStore.Open(filepath.Join(importStore.localStoreFolder, item[field].(string)))
				if err != nil {
					return err
				}
				if _, err = io.Copy(writer, reader); err != nil {
					return err
				}
				if err := mergo.Merge(&item, Item{field: dstPath}); err != nil {
					return err
				}
			}
		}
		_, err = db.Insert(item)
		if err != nil {
			return err
		}
	}
	return err
}

// ExportJSONLite clones the JSONLite database.
func (db *JSONLite) ExportJSONLite(url string) (err error) {
	err = db.cursor.Close()
	if err != nil {
		return err
	}
	remoteFS, remoteFolder, _ := toFS(url)
	err = copy.Directory(db.localFS, remoteFS, db.localStoreFolder, remoteFolder)
	if err != nil {
		return err
	}
	db.cursor, err = sql.Open("sqlite3", db.localDBFile)
	return err
}

// StoreFile adds a file to the database folder.
func (db *JSONLite) StoreFile(filePath string) (storePath string, file afero.File, err error) {
	err = db.MkdirAll(filepath.Join(db.localStoreFolder, filepath.Dir(filePath)), 0755)
	if err != nil {
		return "", nil, err
	}

	db.fileMutex.Lock()
	i := 0
	ext := filepath.Ext(filePath)
	localStoreFilePath := path.Join(db.localStoreFolder, filePath)
	base := localStoreFilePath[:len(localStoreFilePath)-len(ext)]

	exists, err := afero.Exists(db, localStoreFilePath)
	if err != nil {
		db.fileMutex.Unlock()
		return "", nil, err
	}
	for exists {
		localStoreFilePath = fmt.Sprintf("%s_%d%s", base, i, ext)
		i++
		exists, err = afero.Exists(db, localStoreFilePath)
		if err != nil {
			db.fileMutex.Unlock()
			return "", nil, err
		}
	}

	file, err = db.Create(localStoreFilePath)
	db.fileMutex.Unlock()
	return localStoreFilePath[len(db.localStoreFolder)+1:], file, err
}

// func (db *JSONLite) StoreFolder(folderPath string) (absPath, storePath string, err error) {
// 	err = db.MkdirAll(filepath.Directory(folderPath), 0755)
// 	if err != nil {
// 		return "", "", err
// 	}

// 	i := 0
// 	folderPath = path.Join(db.localStoreFolder, folderPath)
// 	base := folderPath

// 	exists, err := afero.Exists(db, folderPath)
// 	if err != nil {
// 		return "", "", err
// 	}
// 	for exists {
// 		folderPath = fmt.Sprintf("%s_%d", base, i)
// 		i++
// 		exists, err = afero.Exists(db, folderPath)
// 		if err != nil {
// 			return "", "", err
// 		}
// 	}

// 	err = db.MkdirAll(folderPath, 0755)
// 	return folderPath, folderPath[len(db.localStoreFolder)+1:], err
// }

// LoadFile opens a file from the database folder.
func (db *JSONLite) LoadFile(path string) (file afero.File, err error) {
	return db.Open(path)
}

// Close saves and closes the database.
func (db *JSONLite) Close() error {
	err := db.cursor.Close()
	if err != nil {
		return err
	}
	if !db.remoteIsLocal {
		err = copy.File(db.localFS, db, db.localDBFile, db.remoteDBFile)
		if err != nil {
			return err
		}
		return db.localFS.Remove(db.localStoreFolder)
	}
	return nil
}

/* ################################
#   Options & Schemas
################################ */

// Discriminator gets the json attribute that seperates objects into tables.
func (db *JSONLite) Discriminator() string {
	value, err := db.option("discriminator")
	if err != nil {
		panic(err)
	}

	if uint8value, ok := value.([]uint8); ok {
		value = string(uint8value)
	}

	return value.(string)
}

// SetDiscriminator sets the json attribute that seperates objects into tables.
func (db *JSONLite) SetDiscriminator(discriminator string) {
	err := db.setOption("discriminator", discriminator)
	if err != nil {
		panic(err)
	}
}

// Strict returns if database is in strict mode and all insertions are validated
// against the contained json schemas.
func (db *JSONLite) Strict() bool {
	value, err := db.option("strict")
	if err != nil {
		panic(err)
	}

	if stringvalue, ok := value.(string); ok {
		value = strings.ToLower(stringvalue) == "true" || stringvalue == "1"
	}

	return value.(bool)
}

// SetStrict set if database is in strict mode and all insertions are validated
// against the contained json schemas.
func (db *JSONLite) SetStrict(strict bool) {
	err := db.setOption("strict", strict)
	if err != nil {
		panic(err)
	}
}

/* ################################
#   Validate
################################ */

// Validate checks the database for variuos flaws.
func (db *JSONLite) Validate() (e []string, err error) {
	e = []string{}
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
		e = append(e, validationErrors...)
		for _, itemExpectedFile := range itemExpectedFiles {
			expectedFiles[filepath.FromSlash(itemExpectedFile)] = true
		}
	}

	foundFiles := map[string]bool{}
	var additionalFiles []string
	err = afero.Walk(db, db.remoteStoreFolder, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, "/item.db-journal") || info.IsDir() {
			return nil
		}
		path = path[len(db.remoteStoreFolder):]

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
		e = append(e, fmt.Sprintf("additional files: ('%s')", strings.Join(additionalFiles, "', '")))
	}

	var missingFiles []string
	for expectedFile := range expectedFiles {
		if _, ok := foundFiles[expectedFile]; !ok {
			missingFiles = append(missingFiles, filepath.ToSlash(expectedFile))
		}
	}

	if len(missingFiles) > 0 {
		e = append(e, fmt.Sprintf("missing files: ('%s')", strings.Join(missingFiles, "', '")))
	}
	return e, nil
}

func (db *JSONLite) validateItem(item Item) (e []string, itemExpectedFiles []string, err error) {
	e = []string{}
	itemExpectedFiles = []string{}

	if _, ok := item[db.Discriminator()]; !ok {
		e = append(e, "item needs to have a discriminator")
	}

	valErr, err := db.validateItemSchema(item)
	if err != nil {
		return nil, nil, err
	}
	e = append(e, valErr...)

	for field := range item {
		if strings.HasSuffix(field, "_path") {
			exportPath := item[field].(string)

			if strings.Contains(exportPath, "..") {
				e = append(e, fmt.Sprintf("'..' in %s", exportPath))
				continue
			}

			itemExpectedFiles = append(itemExpectedFiles, "/"+exportPath)

			exits, err := afero.Exists(db, filepath.Join(db.remoteStoreFolder, exportPath))
			if err != nil {
				return nil, nil, err
			}
			if !exits {
				continue
			}

			if size, ok := item["size"]; ok {
				fi, err := db.Stat(filepath.Join(db.remoteStoreFolder, exportPath))
				if err != nil {
					return nil, nil, err
				}
				if int64(size.(float64)) != fi.Size() {
					e = append(e, fmt.Sprintf("wrong size for %s (is %d, expected %d)", exportPath, fi.Size(), size))
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
						e = append(e, fmt.Sprintf("unsupported hash %s for %s", algorithm, exportPath))
						continue
					}

					f, err := db.Open(filepath.Join(db.remoteStoreFolder, exportPath))
					if err != nil {
						return nil, nil, err
					}

					_, err = io.Copy(h, f)
					f.Close() // nolint:errcheck
					if err != nil {
						return nil, nil, err
					}

					if fmt.Sprintf("%x", h.Sum(nil)) != value {
						e = append(e, fmt.Sprintf("hashvalue mismatch %s for %s", algorithm, exportPath))
					}
				}
			}
		}
	}

	return e, itemExpectedFiles, nil
}

func (db *JSONLite) validateItemSchema(item Item) (e []string, err error) {
	e = []string{}

	rootSchema, err := db.schema(item[db.Discriminator()].(string))
	if err != nil {
		return e, errors.Wrap(err, "could not get root schema")
	}

	db.sqlMutex.Lock()
	for _, schemaName := range db.schemas.keys() {
		schema, _ := db.schemas.load(schemaName)
		jsonschema.DefaultSchemaPool["jsonlite:"+schemaName] = &schema.Schema // TODO fill cache only once
	}

	err = rootSchema.FetchRemoteReferences()
	db.sqlMutex.Unlock()
	if err != nil {
		return e, errors.Wrap(err, "could not FetchRemoteReferences")
	}

	var i map[string]interface{} = item
	var errs []jsonschema.ValError
	rootSchema.Validate("/", i, &errs)
	for _, err := range errs {
		id := ""
		if uid, ok := item["uid"]; ok {
			id = " " + uid.(string)
		}

		e = append(e, errors.Wrap(err, "failed to validate item"+id).Error())
	}
	return e, nil
}

/* ################################
#   Deprecated
################################ */

// Select retreives all items of a discriminated attribute.
func (db *JSONLite) Select(itemType string) (items []Item, err error) {
	stmt, err := db.cursor.Prepare(fmt.Sprintf("SELECT * FROM \"%s\"", itemType)) // #nosec
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
		selectItems, err := db.Select(s)
		if err != nil {
			return nil, err
		}
		items = append(items, selectItems...)
	}
	return
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
					return nil, errors.New("unknownn type")
				}

			default:
				m[colName] = *val
			}
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
		columnRows.Close()
	}
	return tables, nil
}

func (db *JSONLite) ensureTable(flatItem Item, item Item) error {
	db.sqlMutex.Lock()
	defer db.sqlMutex.Unlock()
	if table, ok := db.tables.load(item[db.Discriminator()].(string)); !ok {
		valErr, err := db.validateItemSchema(item)
		if err != nil {
			return errors.Wrap(err, "validation failed")
		}
		if len(valErr) > 0 {
			return fmt.Errorf("item could not be validated [%s]", strings.Join(valErr, ","))
		}
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
			valErr, err := db.validateItemSchema(item)
			if err != nil {
				return err
			}
			if len(valErr) > 0 {
				return fmt.Errorf("item could not be validated [%s]", strings.Join(valErr, ","))
			}
			if err := db.addMissingColumns(item[db.Discriminator()].(string), flatItem, missingColumns); err != nil {
				return errors.Wrap(err, fmt.Sprintf("adding missing column failed %v", missingColumns))
			}
		}
	}
	return nil
}

func (db *JSONLite) createTable(flatItem Item) error {
	table := map[string]string{"uid": "TEXT", db.Discriminator(): "TEXT"}
	db.tables.store(flatItem[db.Discriminator()].(string), table)

	columns := []string{"uid TEXT PRIMARY KEY", db.Discriminator() + " TEXT NOT NULL"}
	for columnName := range flatItem {
		if columnName != "uid" && columnName != db.Discriminator() {
			sqlDataType := getSQLDataType(flatItem[columnName])
			db.tables.innerstore(flatItem[db.Discriminator()].(string), columnName, sqlDataType)
			columns = append(columns, fmt.Sprintf("`%s` %s", columnName, sqlDataType))
		}
	}
	columnText := strings.Join(columns, ", ")

	_, err := db.cursor.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s` (%s)", flatItem[db.Discriminator()], columnText))
	return err
}

func getSQLDataType(value interface{}) string {
	switch value.(type) {
	case int:
		return INTEGER
	case int16:
		return INTEGER
	case int8:
		return INTEGER
	case int32:
		return INTEGER
	case int64:
		return INTEGER
	case uint:
		return INTEGER
	case uint16:
		return INTEGER
	case uint8:
		return INTEGER
	case uint32:
		return INTEGER
	case uint64:
		return INTEGER
	case float32:
		return NUMERIC
	case float64:
		return NUMERIC
	default:
		return TEXT
	}
}

func (db *JSONLite) addMissingColumns(table string, columns map[string]interface{}, newColumns []string) error {
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

func (db *JSONLite) createOptionsTable() error {
	db.sqlMutex.Lock()
	defer db.sqlMutex.Unlock()
	_, err := db.cursor.Exec("CREATE TABLE IF NOT EXISTS \"_options\" (key TEXT PRIMARY KEY, value TEXT)")
	if err != nil {
		return err
	}
	_, err = db.cursor.Exec("CREATE TABLE IF NOT EXISTS \"_schemas\" (id TEXT PRIMARY KEY, schema TEXT)")
	return err
}

func (db *JSONLite) setOption(key string, value interface{}) error {
	if val, ok := db.options.Load(key); ok && val == value {
		return nil
	}

	stmt, err := db.cursor.Prepare("INSERT OR REPLACE INTO \"_options\" (\"key\", \"value\") VALUES (?, ?)")
	if err != nil {
		return err
	}

	db.sqlMutex.Lock()
	_, err = stmt.Exec(key, value)
	db.sqlMutex.Unlock()
	if err != nil {
		return err
	}

	db.options.Store(key, value)
	return nil
}

func (db *JSONLite) option(key string) (interface{}, error) {
	if value, ok := db.options.Load(key); ok {
		return value, nil
	}

	stmt, err := db.cursor.Prepare("SELECT value FROM \"_options\" WHERE \"key\" = ?")
	if err != nil {
		return nil, err
	}

	var value string
	db.sqlMutex.RLock()
	row := stmt.QueryRow(key)
	db.sqlMutex.RUnlock()
	if err := row.Scan(&value); err != nil {
		return nil, err
	}
	db.options.Store(key, value)
	return value, nil
}

// SetSchema inserts or replaces a json schema for input validation.
func (db *JSONLite) SetSchema(id string, schema *jsonschema.RootSchema) error {
	if val, ok := db.schemas.load(id); ok && val == schema {
		return nil
	}

	stmt, err := db.cursor.Prepare("INSERT OR REPLACE INTO \"_schemas\" (\"id\", \"schema\") VALUES (?, ?)")
	if err != nil {
		return err
	}

	schemaData, err := json.Marshal(schema)
	if err != nil {
		return err
	}

	db.sqlMutex.Lock()
	_, err = stmt.Exec(id, schemaData)
	db.sqlMutex.Unlock()
	if err != nil {
		return err
	}

	// db.schemas[id] = schema
	db.schemas.store(id, schema)
	return nil
}

func (db *JSONLite) schema(id string) (*jsonschema.RootSchema, error) {
	if schema, ok := db.schemas.load(id); ok {
		return schema, nil
	}

	stmt, err := db.cursor.Prepare("SELECT schema FROM \"_schemas\" WHERE \"id\" = ?")
	if err != nil {
		return nil, err
	}

	var schemaData string
	schema := &jsonschema.RootSchema{}
	db.sqlMutex.RLock()
	row := stmt.QueryRow(id)
	db.sqlMutex.RUnlock()
	if err := row.Scan(&schemaData); err != nil {
		if err == sql.ErrNoRows {
			return schema, nil
		}

		return nil, errors.Wrap(err, "scanning error")
	}

	if err := json.Unmarshal([]byte(schemaData), schema); err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("unmarshal error %s", schemaData))
	}

	db.schemas.store(id, schema)
	return schema, nil
}

func (db *JSONLite) loadSchemas() error {
	stmt, err := db.cursor.Prepare("SELECT id, schema FROM \"_schemas\"")
	if err != nil {
		return err
	}

	db.sqlMutex.RLock()
	rows, err := stmt.Query()
	db.sqlMutex.RUnlock()
	if err != nil {
		return err
	}

	var id, schemaData string
	for rows.Next() {
		schema := &jsonschema.RootSchema{}
		if err := rows.Scan(&id, &schemaData); err != nil {
			if err == sql.ErrNoRows {
				return nil
			}

			return errors.Wrap(err, "scanning error")
		}

		if err := json.Unmarshal([]byte(schemaData), schema); err != nil {
			return errors.Wrap(err, fmt.Sprintf("unmarshal error %s", schemaData))
		}

		db.schemas.store(id, schema)
	}

	return nil
}
