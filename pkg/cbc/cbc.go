package cbc

import (
	"crypto/cipher"
	"crypto/md5"
	"fmt"
	"github.com/paragor/padding_oracle_attack/pkg/helper"
)


type CBCCipher struct {
	cipherBlock cipher.Block
}

func NewCBCCipher(cipherBlock cipher.Block) *CBCCipher {
	return &CBCCipher{cipherBlock: cipherBlock}
}

func (c *CBCCipher) Encrypt(origin []byte) (result []byte, iv []byte, err error) {
	defer func() {
		if recErr, ok := recover().(string); ok && recErr != "" {
			err = fmt.Errorf(recErr)
		}
	}()
	data := make([]byte, len(origin), len(origin)+c.cipherBlock.BlockSize())
	copy(data, origin)
	data = helper.PKCS5Pad(data, c.cipherBlock.BlockSize())
	hash := md5.Sum(data)
	result = make([]byte, len(data))
	copy(result, hash[:c.cipherBlock.BlockSize()])
	cbcEncryptor := cipher.NewCBCEncrypter(c.cipherBlock, hash[:c.cipherBlock.BlockSize()])
	cbcEncryptor.CryptBlocks(result, data)
	iv = hash[:c.cipherBlock.BlockSize()]
	return
}
func (c *CBCCipher) Decrypt(iv []byte, data []byte) (result []byte, err error) {
	defer func() {
		if recErr, ok := recover().(string); ok && recErr != "" {
			err = fmt.Errorf(recErr)
		}
	}()
	result = make([]byte, len(data))
	cbcDecryptor := cipher.NewCBCDecrypter(c.cipherBlock, iv)
	cbcDecryptor.CryptBlocks(result, data)

	result, err = helper.PKCS5Unpad(result, c.cipherBlock.BlockSize())
	return
}

