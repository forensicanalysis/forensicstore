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

package cmd

import (
	"strings"
	"testing"
)

func TestNormalizeFilePath(t *testing.T) {
	x32 := strings.Repeat("x", 32)
	longFileName := strings.Repeat("long_file_name_", 8)

	pathTests := []struct {
		name              string
		srcPath           string
		normalizedSrcPath string
	}{
		{"Windows path", `/C/Users/user/NTUSER.DAT`, `C_Users_user_NTUSER.DAT`},
		{"Linux path", `/home/username/.bash_history`, `home_username_.bash_history`},
		{
			"Long path",
			`/C/Users/user/AppData/Local/Google/Chrome/User Data/Default/Extensions/` + x32 + `/1.11_1/_metadata/folder_` + x32 + `/` + longFileName + `.json`,
			`AppD_Loca_Goog_Chro_User_Defa_Exte_xxxx_1.11__met_fold_long.json`,
		},
	}

	for _, pt := range pathTests {
		t.Run(pt.name, func(t *testing.T) {
			got := normalizeFilePath(pt.srcPath)

			if got != pt.normalizedSrcPath {
				t.Fatalf("need %v, got %v", pt.normalizedSrcPath, got)
			}
		})
	}
}

func Test_last(t *testing.T) {
	type args struct {
		s string
		n int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"long", args{"abcdef", 2}, "ef"},
		{"short", args{"abc", 4}, "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := last(tt.args.s, tt.args.n); got != tt.want {
				t.Errorf("last() = %v, want %v", got, tt.want)
			}
		})
	}
}
