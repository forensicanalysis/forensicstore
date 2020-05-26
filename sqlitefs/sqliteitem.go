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

package sqlitefs

import (
	"compress/flate"
	"errors"
	"io"
	"log"
	"os"
	"path"

	"github.com/forensicanalysis/forensicstore/sqlitefs/spooled"
)

const MaxMemoryBackedSize = 256 * 1024 * 1024

var ErrNotImplemented = errors.New("not implemented")

type item struct {
	fs   *FS
	path string

	// uncompressor item
	info         os.FileInfo
	children     []os.FileInfo
	uncompressor io.Reader
	blob         io.ReadCloser

	// writer item
	id          int64
	size        int64
	compressor  io.Writer
	writeBuffer *spooled.TemporaryFile
	teardown    func() error
}

func newWriteItem(fs *FS, id int64, path string) (i *item, err error) {
	buf, teardown := spooled.New(MaxMemoryBackedSize)
	i = &item{fs: fs, id: id, path: path, writeBuffer: buf, teardown: teardown}

	i.compressor, err = flate.NewWriter(i.writeBuffer, -1)

	return i, err
}

func newReadItem(fs *FS, id int64, path string, info os.FileInfo, children []os.FileInfo) (i *item, err error) {
	i = &item{fs: fs, path: path, info: info, children: children}

	if !info.IsDir() {
		i.blob, err = i.fs.cursor.OpenBlob("", "sqlar", "data", id, false)
		if err != nil {
			return nil, err
		}

		i.uncompressor = flate.NewReader(i.blob)
	}

	return i, nil
}

func (i *item) Name() string {
	return path.Base(i.path)
}

func (i *item) Read(p []byte) (n int, err error) {
	return i.uncompressor.Read(p)
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
	return i.compressor.Write(p)
}

func (i *item) WriteAt(p []byte, off int64) (n int, err error) {
	return 0, ErrNotImplemented
}

func (i *item) WriteString(s string) (ret int, err error) {
	return i.Write([]byte(s))
}

func (i *item) Close() error {
	if i.uncompressor != nil && i.blob != nil {
		if closer, ok := i.uncompressor.(io.Closer); ok {
			err := closer.Close()
			if err != nil {
				return err
			}
		}
		return i.blob.Close()
	} else if i.compressor != nil {
		if closer, ok := i.compressor.(io.Closer); ok {
			err := closer.Close()
			if err != nil {
				return err
			}
		}

		stmt := i.fs.cursor.Prep(`UPDATE sqlar SET sz = $sz, data = $data WHERE name = $name`)

		size, err := i.writeBuffer.Size()
		if err != nil {
			return err
		}

		stmt.SetText("$name", i.path)
		stmt.SetZeroBlob("$data", size)
		stmt.SetInt64("$sz", i.size)

		_, err = stmt.Step()
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
		defer func() {
			err := data.Close()
			if err != nil {
				log.Println(err)
			}
		}()
		defer func() {
			err := i.teardown()
			if err != nil {
				log.Println(err)
			}
		}()

		_, err = io.Copy(data, i.writeBuffer)
		return err
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
	if i.compressor != nil {
		if flusher, ok := i.compressor.(Flusher); ok {
			return flusher.Flush()
		}
	}
	return nil
}

func (i *item) Reset() {
	i.size = 0
	if err := i.writeBuffer.Close(); err != nil {
		log.Println(err)
	}
}
