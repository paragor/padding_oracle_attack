package helper

import (
	"bytes"
	"fmt"
)

var PaddingError error = fmt.Errorf("padding error")

func PKCS5Pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Unpad(ciphertext []byte, blockSize int) ([]byte, error) {
	last := ciphertext[len(ciphertext)-1]
	if last < 1 {
		return nil, fmt.Errorf("%w: last byte greater then 1", PaddingError)
	}
	if int(last) > blockSize {
		return nil, fmt.Errorf("%w: last byte greater then blocksize", PaddingError)
	}
	if int(last) > len(ciphertext) {
		return nil, fmt.Errorf("%w: last byte greater then ciphertext len", PaddingError)
	}
	for i := len(ciphertext) - int(last); i < len(ciphertext); i++ {
		if last != ciphertext[i] {
			return nil, fmt.Errorf("%w: %d byte (val %x) not equal last byte (val %x)", PaddingError, i, ciphertext[i], last)
		}
	}

	padding := ciphertext[len(ciphertext)-1]
	return ciphertext[:len(ciphertext)-int(padding)], nil
}
