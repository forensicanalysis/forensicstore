package cmd

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/forensicanalysis/forensicstore"
)

func stdout(f func()) []byte {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	outC := make(chan []byte)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r) // nolint
		outC <- buf.Bytes()
	}()

	w.Close()
	os.Stdout = old
	return <-outC
}

func setup(t *testing.T) (string, string) {
	dir, err := ioutil.TempDir("", "forensicstorecmd")
	if err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadFile(filepath.Join("..", "test", "forensicstore", "example1.forensicstore"))
	if err != nil {
		t.Fatal(err)
	}

	storePath := filepath.Join(dir, "example1.forensicstore")
	err = ioutil.WriteFile(storePath, b, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	return dir, storePath
}

func Test_allCommand(t *testing.T) {
	dir, storePath := setup(t)
	defer os.RemoveAll(dir)

	outputString := "[" +
		"{\"artifact\":\"IPTablesRules\",\"command_line\":\"/sbin/iptables -L -n -v\",\"created_time\":\"2016-01-20T14:11:25.550Z\",\"cwd\":\"/root/\",\"id\":\"process--920d7c41-0fef-4cf8-bce2-ead120f6b506\"," +
		"\"name\":\"iptables\",\"return_code\":0,\"stderr_path\":\"IPTablesRules/stderr\",\"stdout_path\":\"IPTablesRules/stdout\",\"type\":\"process\"}," +
		"{\"artifact\":\"WMILogicalDisks\",\"command_line\":\"powershell \\\"gwmi -Query \\\\\\\"SELECT * FROM Win32_LogicalDisk\\\\\\\"\\\"\",\"created_time\":\"2016-01-20T14:11:25.550Z\"," +
		"\"cwd\":\"/root/\",\"id\":\"process--9da4aa39-53b8-412e-b3cd-6b26c772ad4d\",\"name\":\"powershell\",\"return_code\":0,\"stderr_path\":\"WMILogicalDisks/stderr\"," +
		"\"stdout_path\":\"WMILogicalDisks/stdout\",\"type\":\"process\"}," +
		"{\"artifact\":\"WindowsRunKeys\",\"id\":\"windows-registry-key--286a78b9-e8e1-4d89-9a3b-6001c817ea64\"," +
		"\"key\":\"HKEY_USERS\\\\S-1-5-21-7623811015-3361044348-030300820-1013\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\",\"modified_time\":\"2013-11-19T22:46:05.668Z\"," +
		"\"type\":\"windows-registry-key\"}," +
		"{\"artifact\":\"WindowsCodePage\",\"id\":\"windows-registry-key--4125428d-cfad-466d-8f2d-a72f9aac6687\"," +
		"\"key\":\"HKEY_LOCAL_MACHINE\\\\System\\\\CurrentControlSet\\\\Control\\\\Nls\\\\CodePage\",\"modified_time\":\"2009-07-14T04:34:14.225Z\"," +
		"\"type\":\"windows-registry-key\",\"values\":[{\"data\":\"1252\",\"data_type\":\"REG_SZ\",\"name\":\"ACP\"}]}," +
		"{\"artifact\":\"WindowsAMCacheHveFile\",\"atime\":\"2014-09-11T21:50:18.301Z\",\"ctime\":\"2014-09-11T21:50:18.301Z\",\"export_path\":\"WindowsAMCacheHveFile/Amcache.hve\"," +
		"\"hashes\":{\"MD5\":\"9b573b2e4c4b91558f6afd65262a6fb9\",\"SHA-1\":\"932567a1cfc045b729abdb52ed6c5c6acf59f369\"},\"id\":\"file--ddc3b32f-a1ea-4888-87ca-5591773f6be3\",\"mtime\":\"2014-09-11T21:50:18.301Z\"," +
		"\"name\":\"Amcache.hve\",\"origin\":{\"path\":\"C:\\\\Windows\\\\appcompat\\\\Programs\\\\Amcache.hve\",\"volumne\":2},\"size\":123,\"type\":\"file\"}," +
		"{\"artifact\":\"WindowsUserDownloadsDirectory\",\"atime\":\"2014-09-11T21:50:18.301Z\",\"ctime\":\"2014-09-11T21:50:18.301Z\",\"export_path\":\"WindowsAMCacheHveFile/Amcache.hve\"," +
		"\"hashes\":{\"MD5\":\"9b573b2e4c4b91558f6afd65262a6fb9\",\"SHA-1\":\"932567a1cfc045b729abdb52ed6c5c6acf59f369\"},\"id\":\"file--7408798b-6f09-49dd-a3a0-c54fba59c38c\",\"mtime\":\"2014-09-11T21:50:18.301Z\"," +
		"\"name\":\"foo.doc\",\"origin\":{\"path\":\"C:\\\\Users\\\\bob\\\\Downloads\\\\foo.doc\",\"volumne\":2},\"size\":123,\"type\":\"file\"}," +
		"{\"artifact\":\"WindowsEnvironmentVariableProgramFiles\"," +
		"\"atime\":\"2014-09-11T21:50:18.301Z\",\"ctime\":\"2014-09-11T21:50:18.301Z\",\"id\":\"directory--ed070d8c-c8d9-40ab-ae18-3f6b6725b7a7\",\"mtime\":\"2014-09-11T21:50:18.301Z\"," +
		"\"path\":\"C:\\\\Program Files\",\"type\":\"directory\"}]"
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"all", []string{storePath}, outputString, false},
	}
	for _, tt := range tests {
		cmd := allCommand()
		cmd.Flags().Parse(tt.args)

		output := stdout(func() {
			err := cmd.RunE(cmd, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("allCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})

		if string(output) != tt.want {
			t.Errorf("allCommand got = %v, want %v", string(output), tt.want)
		}
	}
}

func Test_getCommand(t *testing.T) {
	dir, storePath := setup(t)
	defer os.RemoveAll(dir)


	outputString := "{\"artifact\":\"WMILogicalDisks\"," +
		"\"command_line\":\"powershell \\\"gwmi -Query \\\\\\\"SELECT * FROM Win32_LogicalDisk\\\\\\\"\\\"\"," +
		"\"created_time\":\"2016-01-20T14:11:25.550Z\"," +
		"\"cwd\":\"/root/\"," +
		"\"id\":\"process--9da4aa39-53b8-412e-b3cd-6b26c772ad4d\"," +
		"\"name\":\"powershell\"," +
		"\"return_code\":0," +
		"\"stderr_path\":\"WMILogicalDisks/stderr\"," +
		"\"stdout_path\":\"WMILogicalDisks/stdout\"," +
		"\"type\":\"process\"}\n"
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"get", []string{"process--9da4aa39-53b8-412e-b3cd-6b26c772ad4d", storePath}, outputString, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := getCommand()
			cmd.Flags().Parse(tt.args)

			output := stdout(func() {
				err := cmd.RunE(cmd, tt.args)
				if (err != nil) != tt.wantErr {
					t.Errorf("getCommand() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			})

			if string(output) != tt.want {
				t.Errorf("getCommand got = %v, want %v", string(output), tt.want)
			}
		})
	}
}

func Test_insertCommand(t *testing.T) {
	dir, storePath := setup(t)
	defer os.RemoveAll(dir)

	inputString := "{\"artifact\":\"WMILogicalDisks\"," +
		"\"command_line\":\"powershell \\\"gwmi -Query \\\\\\\"SELECT * FROM Win32_LogicalDisk\\\\\\\"\\\"\"," +
		"\"created_time\":\"2016-01-20T14:11:25.550Z\"," +
		"\"cwd\":\"/root/\"," +
		"\"id\":\"process--9da4aa39-53b8-412e-b3cd-6b26c772ad4d\"," +
		"\"name\":\"powershell\"," +
		"\"return_code\":0," +
		"\"stderr_path\":\"WMILogicalDisks/stderr\"," +
		"\"stdout_path\":\"WMILogicalDisks/stdout\"," +
		"\"type\":\"process\"}\n"
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"insert", []string{inputString, storePath}, "process--9da4aa39-53b8-412e-b3cd-6b26c772ad4d\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := insertCommand()
			cmd.Flags().Parse(tt.args)

			output := stdout(func() {
				err := cmd.RunE(cmd, tt.args)
				if (err != nil) != tt.wantErr {
					t.Errorf("getCommand() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			})

			if string(output) != tt.want {
				t.Errorf("getCommand got = %v, want %v", string(output), tt.want)
			}
		})
	}
}

func Test_printElements(t *testing.T) {
	type args struct {
		elements []forensicstore.JSONElement
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"printElements", args{elements: []forensicstore.JSONElement{[]byte(`"test"`), []byte(`"foo"`)}}, `["test","foo"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := stdout(func() {
				printElements(tt.args.elements)
			})

			if string(output) != tt.want {
				t.Errorf("printElements got = %v, want %v", string(output), tt.want)
			}
		})
	}
}

func Test_selectCommand(t *testing.T) {
	dir, storePath := setup(t)
	defer os.RemoveAll(dir)

	outputString := "[{\"artifact\":\"IPTablesRules\"," +
		"\"command_line\":\"/sbin/iptables -L -n -v\"," +
		"\"created_time\":\"2016-01-20T14:11:25.550Z\"," +
		"\"cwd\":\"/root/\",\"id\":\"process--920d7c41-0fef-4cf8-bce2-ead120f6b506\"," +
		"\"name\":\"iptables\"," +
		"\"return_code\":0," +
		"\"stderr_path\":\"IPTablesRules/stderr\"," +
		"\"stdout_path\":\"IPTablesRules/stdout\"," +
		"\"type\":\"process\"}," +
		"{\"artifact\":\"WMILogicalDisks\"," +
		"\"command_line\":\"powershell \\\"gwmi -Query \\\\\\\"SELECT * FROM Win32_LogicalDisk\\\\\\\"\\\"\"," +
		"\"created_time\":\"2016-01-20T14:11:25.550Z\"," +
		"\"cwd\":\"/root/\"," +
		"\"id\":\"process--9da4aa39-53b8-412e-b3cd-6b26c772ad4d\"," +
		"\"name\":\"powershell\"," +
		"\"return_code\":0," +
		"\"stderr_path\":\"WMILogicalDisks/stderr\"," +
		"\"stdout_path\":\"WMILogicalDisks/stdout\"," +
		"\"type\":\"process\"}]"
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"select", []string{"process", storePath}, outputString, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := selectCommand()
			cmd.Flags().Parse(tt.args)

			output := stdout(func() {
				err := cmd.RunE(cmd, tt.args)
				if (err != nil) != tt.wantErr {
					t.Errorf("getCommand() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			})

			if string(output) != tt.want {
				t.Errorf("getCommand got = %v, want %v", string(output), tt.want)
			}
		})
	}
}
