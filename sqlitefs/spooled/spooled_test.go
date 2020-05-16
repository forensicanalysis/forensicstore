package spooled

import (
	"bytes"
	"reflect"
	"testing"
)

func TestTemporaryFile_Close(t1 *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"close", false},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t, _ := New(10)

			if err := t.Close(); (err != nil) != tt.wantErr {
				t1.Errorf("Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTemporaryFile_Read(t1 *testing.T) {
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		args    args
		wantN   int
		wantErr bool
	}{
		{"small read", args{make([]byte, 1)}, 1, false},
		{"large read", args{make([]byte, 100)}, 100, false},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t, teardown := New(10)
			defer teardown()

			_, err := t.Write(bytes.Repeat([]byte("abcd"), 100))
			if err != nil {
				t1.Fatal(err)
			}

			gotN, err := t.Read(tt.args.p)
			if (err != nil) != tt.wantErr {
				t1.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t1.Errorf("Read() gotN = %v, want %v", gotN, tt.wantN)
			}
			if !reflect.DeepEqual(tt.args.p, bytes.Repeat([]byte("abcd"), 25)[:tt.wantN]) {
				t1.Errorf("Read() = %v, want %v", tt.args.p, "25 * 'abcd'")
			}
		})
	}
}

func TestTemporaryFile_Rollover(t1 *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"rollover", false},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t, teardown := New(10)
			defer teardown()

			if err := t.Rollover(); (err != nil) != tt.wantErr {
				t1.Errorf("Rollover() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !t.rolledOver {
				t1.Errorf("t.rolledOver should be true")
			}
		})
	}
}

func TestTemporaryFile_Size(t1 *testing.T) {
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		args    args
		want    int64
		wantErr bool
	}{
		{"small size", args{[]byte("abc")}, 3, false},
		{"large size", args{bytes.Repeat([]byte("abc"), 10)}, 30, false},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t, teardown := New(10)
			defer teardown()

			t.Write(tt.args.p)

			got, err := t.Size()
			if (err != nil) != tt.wantErr {
				t1.Errorf("Size() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t1.Errorf("Size() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTemporaryFile_Write(t1 *testing.T) {
	type args struct {
		p []byte
	}
	tests := []struct {
		name           string
		args           args
		wantN          int
		wantRolledOver bool
		wantErr        bool
	}{
		{"small write", args{[]byte("abc")}, 3, false, false},
		{"large write", args{bytes.Repeat([]byte("abc"), 10)}, 30, true, false},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t, teardown := New(10)
			defer teardown()

			gotN, err := t.Write(tt.args.p)
			if (err != nil) != tt.wantErr {
				t1.Errorf("Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t1.Errorf("Write() gotN = %v, want %v", gotN, tt.wantN)
			}
			if t.rolledOver != tt.wantRolledOver {
				t1.Errorf("t.rolledOver should be %t", tt.wantRolledOver)
			}
		})
	}
}

func TestTemporaryFile_DoubleWrite(t1 *testing.T) {
	type args struct {
		p []byte
	}
	tests := []struct {
		name           string
		args           args
		wantN          int
		wantRolledOver bool
		wantErr        bool
	}{
		{"large write", args{bytes.Repeat([]byte("abc"), 10)}, 30, true, false},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t, teardown := New(10)
			defer teardown()

			_, err := t.Write(tt.args.p)
			if (err != nil) != tt.wantErr {
				t1.Errorf("Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			gotN, err := t.Write(tt.args.p)
			if (err != nil) != tt.wantErr {
				t1.Errorf("Write() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotN != tt.wantN {
				t1.Errorf("Write() gotN = %v, want %v", gotN, tt.wantN)
			}
			if t.rolledOver != tt.wantRolledOver {
				t1.Errorf("t.rolledOver should be %t", tt.wantRolledOver)
			}
		})
	}
}
