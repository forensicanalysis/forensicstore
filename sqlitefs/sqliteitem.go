package sqlitefs

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"os"
	"path"
)

var ErrNotImplemented = errors.New("not implemented")

type item struct {
	fs   *FS
	path string
	buf  *bytes.Buffer

	// reader item
	reader io.Reader
	info   os.FileInfo
	data   io.ReadCloser

	children []os.FileInfo

	// writer item
	id     int64
	writer io.Writer
	size   int64
}

func newWriteItem(fs *FS, id int64, path string) (*item, error) {
	i := &item{fs: fs, id: id, path: path, buf: &bytes.Buffer{}}

	var err error

	i.writer, err = flate.NewWriter(i.buf, -1)

	return i, err
}

func newReadItem(fs *FS, id int64, path string, info os.FileInfo, children []os.FileInfo) (*item, error) {
	i := &item{fs: fs, path: path, info: info, children: children}

	if !info.IsDir() {
		var err error
		i.data, err = i.fs.cursor.OpenBlob("", "sqlar", "data", id, false)
		if err != nil {
			return nil, err
		}

		i.reader = flate.NewReader(i.data)
	}

	return i, nil
}

func (i *item) Name() string {
	return path.Base(i.path)
}

func (i *item) Read(p []byte) (n int, err error) {
	return i.reader.Read(p)
}

func (i *item) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, ErrNotImplemented
}

func (i *item) Seek(offset int64, whence int) (int64, error) {
	return 0, ErrNotImplemented
}

func (i *item) Readdir(count int) ([]os.FileInfo, error) {
	n := len(i.children)
	if count > 0 && count < n {
		n = count
	}
	return i.children[:n], nil
}

func (i *item) Readdirnames(n int) ([]string, error) {
	var names []string
	for c, child := range i.children {
		if c > n && n > 0 {
			break
		}
		names = append(names, child.Name())
	}
	return names, nil
}

func (i *item) Stat() (os.FileInfo, error) {
	return i.info, nil
}

func (i *item) Write(p []byte) (n int, err error) {
	i.size += int64(len(p))
	return i.writer.Write(p)
}

func (i *item) WriteAt(p []byte, off int64) (n int, err error) {
	return 0, ErrNotImplemented
}

func (i *item) WriteString(s string) (ret int, err error) {
	return i.Write([]byte(s))
}

func (i *item) Close() error {
	if i.reader != nil && i.data != nil {
		if closer, ok := i.reader.(io.Closer); ok {
			err := closer.Close()
			if err != nil {
				return err
			}
		}
		return i.data.Close()
	} else if i.writer != nil {
		if closer, ok := i.writer.(io.Closer); ok {
			err := closer.Close()
			if err != nil {
				return err
			}
		}

		stmt := i.fs.cursor.Prep(`UPDATE sqlar SET sz = $sz, data = $data WHERE name = $name`)

		stmt.SetText("$name", i.path)
		stmt.SetZeroBlob("$data", int64(i.buf.Len()))
		stmt.SetInt64("$sz", i.size)

		_, err := stmt.Step()
		if err != nil {
			return err
		}

		err = stmt.Finalize()
		if err != nil {
			return err
		}

		data, err := i.fs.cursor.OpenBlob("", "sqlar", "data", i.id, true)
		if err != nil {
			return err
		}

		_, err = io.Copy(data, i.buf)
		if err != nil {
			return err
		}

		return data.Close()
	}
	return nil
}

func (i *item) Truncate(size int64) error {
	return ErrNotImplemented
}

type Flusher interface {
	Flush() error
}

func (i *item) Sync() error {
	if i.writer != nil {
		if flusher, ok := i.writer.(Flusher); ok {
			return flusher.Flush()
		}
	}
	return nil
}
