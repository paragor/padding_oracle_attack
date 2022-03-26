package cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCBCCipher_Encrypt_Decrypt(t *testing.T) {
	type fields struct {
		cipherBlock cipher.Block
	}
	type args struct {
		origin []byte
	}
	aesCipher, err := aes.NewCipher(bytes.Repeat([]byte{0x1}, aes.BlockSize))
	if err != nil {
		panic(err)
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		wantErrEncrypt bool
		wantErrDecrypt bool
	}{
		{
			name: "simple",
			fields: fields{
				cipherBlock: aesCipher,
			},
			args: args{
				origin: []byte("hui"),
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "13",
			fields: fields{
				cipherBlock: aesCipher,
			},
			args: args{
				origin: bytes.Repeat([]byte{13}, 13),
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CBCCipher{
				cipherBlock: tt.fields.cipherBlock,
			}
			encrypted, iv, err := c.Encrypt(tt.args.origin)
			if (err != nil) != tt.wantErrEncrypt {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErrEncrypt)
				return
			}

			assert.NotEqual(t, tt.args.origin, encrypted)

			decrypted, err := c.Decrypt(iv, encrypted)
			if (err != nil) != tt.wantErrDecrypt {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErrDecrypt)
				return
			}
			assert.Equal(t, tt.args.origin, decrypted)
		})
	}
}
