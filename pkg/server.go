package pkg

import (
	"bytes"
	"errors"
	"github.com/paragor/padding_oracle_attack/pkg/cbc"
	"github.com/paragor/padding_oracle_attack/pkg/helper"
)

type SiegeServer interface {
	VerifyPadding(data []byte) (isDecrypted bool, isPaddingError bool, err error)
}

type LocalServer struct {
	cbc       *cbc.CBCCipher
	originMsg []byte
	iv        []byte
}

func NewLocalServer(cbc *cbc.CBCCipher, originMsg []byte, iv []byte) *LocalServer {
	return &LocalServer{cbc: cbc, originMsg: originMsg, iv: iv}
}

func (s *LocalServer) VerifyPadding(data []byte) (bool, bool, error) {
	decrypted, err := s.cbc.Decrypt(s.iv, data)
	if err != nil {
		if errors.Is(err, helper.PaddingError) {
			return false, true, nil
		}

		return false, false, err
	}

	return bytes.Equal(decrypted, data), false, nil
}
