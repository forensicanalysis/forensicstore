package sqlitefs

import (
	"compress/flate"
	"github.com/forensicanalysis/forensicstore/sqlitefs/spooled"
	"io"
	"os"
	"reflect"
	"testing"
)

func TestNewReadItem(t *testing.T) {
	type args struct {
		fs       *FS
		id       int64
		path     string
		info     os.FileInfo
		children []os.FileInfo
	}
	tests := []struct {
		name    string
		args    args
		want    *item
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newReadItem(tt.args.fs, tt.args.id, tt.args.path, tt.args.info, tt.args.children)
			if (err != nil) != tt.wantErr {
				t.Errorf("newReadItem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newReadItem() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewWriteItem(t *testing.T) {
	type args struct {
		fs   *FS
		id   int64
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    *item
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newWriteItem(tt.args.fs, tt.args.id, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("newWriteItem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newWriteItem() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_item_Close(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			if err := i.Close(); (err != nil) != tt.wantErr {
				t.Errorf("Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_item_Name(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			if got := i.Name(); got != tt.want {
				t.Errorf("Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_item_Read(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantN   int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			gotN, err := i.Read(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("Read() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func Test_item_ReadAt(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		p   []byte
		off int64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantN   int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			gotN, err := i.ReadAt(tt.args.p, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadAt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("ReadAt() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func Test_item_Readdir(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		count int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []os.FileInfo
		wantErr bool
	}{
		{"readdir", fields{}, args{}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			got, err := i.Readdir(tt.args.count)
			if (err != nil) != tt.wantErr {
				t.Errorf("Readdir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Readdir() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_item_Readdirnames(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		n int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []string
		wantErr bool
	}{
		{"readdirnames", fields{}, args{}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			got, err := i.Readdirnames(tt.args.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("Readdirnames() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Readdirnames() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_item_Seek(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		offset int64
		whence int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    int64
		wantErr bool
	}{
		{"seek", fields{}, args{}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			got, err := i.Seek(tt.args.offset, tt.args.whence)
			if (err != nil) != tt.wantErr {
				t.Errorf("Seek() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Seek() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_item_Stat(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	tests := []struct {
		name    string
		fields  fields
		want    os.FileInfo
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			got, err := i.Stat()
			if (err != nil) != tt.wantErr {
				t.Errorf("Stat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Stat() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_item_Sync(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			if err := i.Sync(); (err != nil) != tt.wantErr {
				t.Errorf("Sync() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_item_Truncate(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		size int64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"truncate", fields{}, args{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			if err := i.Truncate(tt.args.size); (err != nil) != tt.wantErr {
				t.Errorf("Truncate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_item_Write(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantN   int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			gotN, err := i.Write(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("Write() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func Test_item_WriteAt(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		p   []byte
		off int64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantN   int
		wantErr bool
	}{
		{"writeat", fields{}, args{}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			gotN, err := i.WriteAt(tt.args.p, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteAt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("WriteAt() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func Test_item_WriteString(t *testing.T) {
	type fields struct {
		fs          *FS
		path        string
		buf         *spooled.TemporaryFile
		flateReader io.ReadCloser
		info        os.FileInfo
		data        io.ReadCloser
		id          int64
		writer      *flate.Writer
		size        int64
	}
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantRet int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &item{
				fs:           tt.fields.fs,
				path:         tt.fields.path,
				writeBuffer:  tt.fields.buf,
				uncompressor: tt.fields.flateReader,
				info:         tt.fields.info,
				blob:         tt.fields.data,
				id:           tt.fields.id,
				compressor:   tt.fields.writer,
				size:         tt.fields.size,
			}
			gotRet, err := i.WriteString(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRet != tt.wantRet {
				t.Errorf("WriteString() gotRet = %v, want %v", gotRet, tt.wantRet)
			}
		})
	}
}
