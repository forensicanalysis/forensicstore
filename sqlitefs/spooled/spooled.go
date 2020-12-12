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

package spooled

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type TemporaryFile struct {
	size       int64
	maxSize    int64
	buffer     *bytes.Buffer
	tempFile   *os.File
	rolledOver bool
}

func New(maxSize int64) (*TemporaryFile, func() error) {
	t := &TemporaryFile{buffer: &bytes.Buffer{}, maxSize: maxSize}
	return t, t.Close
}

func (t *TemporaryFile) Read(p []byte) (n int, err error) {
	if t.rolledOver {
		_, err := t.tempFile.Seek(0, os.SEEK_SET)
		if err != nil {
			return len(p), err
		}
		return t.tempFile.Read(p)
	}
	return t.buffer.Read(p)
}

func (t *TemporaryFile) Write(p []byte) (n int, err error) {
	if t.rolledOver {
		return t.tempFile.Write(p)
	}

	t.size += int64(len(p))

	if t.size > t.maxSize {
		err := t.Rollover()
		if err != nil {
			return len(p), err
		}
		return t.tempFile.Write(p)
	}

	return t.buffer.Write(p)
}

func (t *TemporaryFile) Rollover() (err error) {
	t.tempFile, err = ioutil.TempFile(".", "tmp")
	if err != nil {
		return fmt.Errorf("could not create tmp file: %w", err)
	}
	t.rolledOver = true
	_, err = io.Copy(t.tempFile, t.buffer)
	if err != nil {
		return fmt.Errorf("could not fill tmp file: %w", err)
	}
	t.buffer.Reset()
	return nil
}

func (t *TemporaryFile) Close() error {
	if t.rolledOver {
		err := t.tempFile.Close()
		if err != nil {
			return err
		}
		return os.Remove(t.tempFile.Name())
	}
	t.buffer.Reset()
	return nil
}

func (t *TemporaryFile) Size() (int64, error) {
	if t.rolledOver {
		info, err := t.tempFile.Stat()
		if err != nil {
			return 0, err
		}
		return info.Size(), nil
	}
	return int64(t.buffer.Len()), nil
}
