package forensicstore

import "testing"

func Test_validateSchema(t *testing.T) {
	testElement1 := jsons(map[string]interface{}{
		"id":   "file--920d7c41-0fef-4cf8-bce2-ead120f6b506",
		"type": "file",
		"name": "foo.txt",
		"hashes": map[string]interface{}{
			"MD5": "0356a89e11fcbed1288a0553377541af",
		},
	})
	testElement2 := jsons(element{
		"id":   "file--920d7c41-0fef-4cf8-bce2-ead120f6b506",
		"type": "file",
		"foo":  "foo.txt",
	})

	type args struct {
		element JSONElement
	}
	tests := []struct {
		name      string
		args      args
		wantFlaws int
		wantErr   bool
	}{
		{"valid", args{testElement1}, 0, false},
		{"invalid", args{testElement2}, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupSchemaValidation()
			gotFlaws, err := validateSchema(tt.args.element)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(gotFlaws) != tt.wantFlaws {
				t.Errorf("validateSchema() = %v, want %v", gotFlaws, tt.wantFlaws)
			}
		})
	}
}
