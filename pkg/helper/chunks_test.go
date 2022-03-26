package helper

import (
	"reflect"
	"testing"
)

func TestSplitData(t *testing.T) {
	type args struct {
		data         []byte
		maxChunkSize int
	}
	tests := []struct {
		name    string
		args    args
		want    [][]byte
		wantErr bool
	}{
		{
			name: "10/3",
			args: args{
				data:         []byte("1234567890"),
				maxChunkSize: 3,
			},
			want: [][]byte{
				[]byte("123"),
				[]byte("456"),
				[]byte("789"),
				[]byte("0"),
			},
			wantErr: false,
		},
		{
			name: "10/2",
			args: args{
				data:         []byte("1234567890"),
				maxChunkSize: 2,
			},
			want: [][]byte{
				[]byte("12"),
				[]byte("34"),
				[]byte("56"),
				[]byte("78"),
				[]byte("90"),
			},
			wantErr: false,
		},
		{
			name: "1/1",
			args: args{
				data:         []byte("1"),
				maxChunkSize: 3,
			},
			want: [][]byte{
				[]byte("1"),
			},
			wantErr: false,
		},
		{
			name: "0/0",
			args: args{
				data:         []byte(""),
				maxChunkSize: 0,
			},
			want: [][]byte{},
			wantErr: true,
		},
		{
			name: "10/11",
			args: args{
				data:         []byte("1234567890"),
				maxChunkSize: 10,
			},
			want: [][]byte{
				[]byte("1234567890"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SplitData(tt.args.data, tt.args.maxChunkSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("SplitData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitData() got = %v, want %v", got, tt.want)
			}
		})
	}
}
