package sqlitefs

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"crawshaw.io/sqlite"
	"github.com/spf13/afero"
)

type FS struct {
	cursor *sqlite.Conn
}

const table = `CREATE TABLE IF NOT EXISTS sqlar(
  name TEXT PRIMARY KEY,  -- name of the file
  mode INT,               -- access permissions
  mtime INT,              -- last modification time
  sz INT,                 -- original file size
  data BLOB               -- compressed content
);`

func New(url string) (*FS, error) {
	var err error
	fs := &FS{}

	fs.cursor, err = sqlite.OpenConn(url, 0)
	if err != nil {
		return nil, err
	}

	stmt := fs.cursor.Prep(table)
	err = exec(stmt)

	return fs, err
}

func (fs *FS) Chmod(name string, mode os.FileMode) error {
	name = normalizeFilename(name)
	stmt := fs.cursor.Prep("UPDATE sqlar SET mode = $mode WHERE name = $name")
	stmt.SetText("$name", name)
	stmt.SetInt64("$mode", int64(mode))
	return exec(stmt)
}

func (fs *FS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	name = normalizeFilename(name)
	stmt := fs.cursor.Prep("UPDATE sqlar SET mtime = $mtime WHERE name = $name")
	stmt.SetText("$name", name)
	stmt.SetInt64("$mtime", mtime.Unix())
	return exec(stmt)
}

func (fs *FS) Create(name string) (afero.File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (fs *FS) Mkdir(name string, perm os.FileMode) error {
	name = normalizeFilename(name)

	stmt := fs.cursor.Prep(`INSERT INTO sqlar (name, mode, mtime, sz, data) VALUES ($name, $mode, $mtime, $sz, $data)`)

	stmt.SetText("$name", name)
	stmt.SetInt64("$mode", int64(perm))
	stmt.SetInt64("$mtime", time.Now().Unix())
	stmt.SetInt64("$sz", 0)
	stmt.SetNull("$data")

	return exec(stmt)
}

func (fs *FS) MkdirAll(p string, perm os.FileMode) error {
	p = normalizeFilename(p)
	_ = fs.Mkdir("/", perm)
	all := ""
	parts := strings.Split(p, "/")
	for _, part := range parts {
		all = path.Join(all, part)
		_ = fs.Mkdir(all, perm)
	}
	return nil
}

func (fs *FS) Name() string {
	return "SQLiteFS"
}

func (fs *FS) Open(name string) (afero.File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

func (fs *FS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	name = normalizeFilename(name)

	var id int64
	var err error
	if flag&os.O_CREATE != 0 {
		id, err = fs.createFile(name, perm)
		if err != nil {
			return nil, err
		}
	} else {
		stmt := fs.cursor.Prep(`SELECT rowid, mode, mtime, sz, CASE WHEN data IS NULL THEN 'TRUE' ELSE 'FALSE' END dataNull FROM sqlar WHERE name = $name`)

		stmt.SetText("$name", name)

		hasRow, err := stmt.Step()
		if err != nil {
			return nil, err
		} else if !hasRow {
			return nil, os.ErrNotExist
		}

		id = stmt.GetInt64("rowid")

		size := stmt.GetInt64("sz")
		info := &Info{
			name:  name,
			sz:    size,
			mode:  os.FileMode(stmt.GetInt64("mode")),
			mtime: time.Unix(stmt.GetInt64("mtime"), 0),
			dir:   size == 0 && stmt.GetText("dataNull") == "TRUE", //nolint:goconst
		}

		err = stmt.Reset()
		if err != nil {
			return nil, err
		}

		// directory
		var children []os.FileInfo
		if info.dir {
			children, err = fs.selectChildren(name, children)
			if err != nil {
				return nil, err
			}
		}

		return newReadItem(fs, id, name, info, children)
	}

	if flag&os.O_RDWR != 0 || flag&os.O_WRONLY != 0 {
		return newWriteItem(fs, id, name)
	}
	return nil, ErrNotImplemented
}

func (fs *FS) selectChildren(name string, children []os.FileInfo) ([]os.FileInfo, error) {
	stmt := fs.cursor.Prep(`SELECT name, mode, mtime, sz, CASE WHEN data IS NULL THEN 'TRUE' ELSE 'FALSE' END dataNull FROM sqlar WHERE name LIKE $name`)
	if name == "/" {
		stmt.SetText("$name", "/%")
	} else {
		stmt.SetText("$name", name+"/%")
	}

	for {
		hasChildRow, err := stmt.Step()
		if err != nil {
			return nil, err
		} else if !hasChildRow {
			break
		}
		childName := stmt.GetText("name")
		if childName == name || strings.Contains(strings.Trim(childName[len(name):], "/"), "/") {
			continue
		}

		childSize := stmt.GetInt64("sz")
		children = append(children, &Info{
			name:  path.Base(childName),
			sz:    childSize,
			mode:  os.FileMode(stmt.GetInt64("mode")),
			mtime: time.Unix(stmt.GetInt64("mtime"), 0),
			dir:   childSize == 0 && stmt.GetText("dataNull") == "TRUE",
		})
	}

	return children, stmt.Finalize()
}

func (fs *FS) createFile(name string, perm os.FileMode) (int64, error) {
	stmt := fs.cursor.Prep(`INSERT INTO sqlar (name, mode, mtime, sz) VALUES ($name, $mode, $mtime, $sz)`)

	stmt.SetText("$name", name)
	stmt.SetInt64("$mode", int64(perm))
	stmt.SetInt64("$mtime", time.Now().Unix())
	stmt.SetInt64("$sz", 0)

	err := exec(stmt)
	if err != nil {
		return 0, fmt.Errorf("failed to create %s: %w", name, err)
	}
	return fs.cursor.LastInsertRowID(), nil
}

func (fs *FS) Remove(name string) error {
	name = normalizeFilename(name)
	stmt := fs.cursor.Prep(`DELETE FROM sqlar WHERE name = $name`)
	stmt.SetText("$name", name)
	return exec(stmt)
}

func (fs *FS) RemoveAll(path string) error {
	path = normalizeFilename(path)
	stmt := fs.cursor.Prep(`DELETE FROM sqlar WHERE name LIKE $name`)
	stmt.SetText("$name", path+"%")
	return exec(stmt)
}

func (fs *FS) Rename(oldname, newname string) error {
	oldname = normalizeFilename(oldname)
	newname = normalizeFilename(newname)

	stmt := fs.cursor.Prep("UPDATE sqlar SET name = $newname WHERE name = $oldname")
	stmt.SetText("$oldname", oldname)
	stmt.SetText("$newname", newname)
	return exec(stmt)
}

func (fs *FS) Stat(name string) (os.FileInfo, error) {
	name = normalizeFilename(name)

	stmt := fs.cursor.Prep("SELECT name, mode, mtime, sz, CASE WHEN data IS NULL THEN 'TRUE' ELSE 'FALSE' END dataNull FROM sqlar WHERE name = $name")

	stmt.SetText("$name", name)

	hasRow, err := stmt.Step()
	if err != nil {
		return nil, err
	} else if !hasRow {
		return nil, os.ErrNotExist
	}

	size := stmt.GetInt64("sz")
	info := &Info{
		name:  path.Base(stmt.GetText("name")),
		sz:    size,
		mode:  os.FileMode(stmt.GetInt64("mode")),
		mtime: time.Unix(stmt.GetInt64("mtime"), 0),
		dir:   size == 0 && stmt.GetText("dataNull") == "TRUE",
	}

	err = stmt.Finalize()
	return info, err
}

func (fs *FS) Close() error {
	return fs.cursor.Close()
}

type Info struct {
	sz    int64
	mtime time.Time
	mode  os.FileMode
	dir   bool
	name  string
}

func (i *Info) Name() string { // base name of the file
	return i.name
}
func (i *Info) Size() int64 { // length in bytes for regular files; system-dependent for others
	return i.sz
}
func (i *Info) Mode() os.FileMode { // file mode bits
	return i.mode
}
func (i *Info) ModTime() time.Time { // modification time
	return i.mtime
}
func (i *Info) IsDir() bool { // abbreviation for Mode().IsDir()
	return i.dir
}
func (i *Info) Sys() interface{} { // underlying data source (can return nil)
	return nil
}

func exec(stmt *sqlite.Stmt) error {
	_, err := stmt.Step()
	if err != nil {
		return err
	}
	return stmt.Finalize()
}

func normalizeFilename(name string) string {
	if name == "." || name == "" || name == "/" {
		return "/"
	}
	name = filepath.ToSlash(name)
	name = "/" + strings.Trim(name, "/")
	return name
}
