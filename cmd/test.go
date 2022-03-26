package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"github.com/paragor/padding_oracle_attack/pkg"
	"github.com/paragor/padding_oracle_attack/pkg/cbc"
	"github.com/paragor/padding_oracle_attack/pkg/poa"
	"log"
)

func main() {

	plaintext := []byte("вышел гена на крыльцо почасать своего кота видит гена в речке рак")
	password := []byte("the most secure password")

	cipher, err := aes.NewCipher(password)
	if err != nil {
		panic(err)
	}
	cbcCipher := cbc.NewCBCCipher(cipher)
	ciphertext, iv, err := cbcCipher.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	server := pkg.NewLocalServer(cbcCipher, plaintext, iv)

	attacker := poa.NewPaddingOracleAttacker(server, log.Default())

	result, err := attacker.Attack(iv, ciphertext, cipher.BlockSize())
	if err != nil {
		panic(err)
	}

	fmt.Println("------------")
	fmt.Println("Done!")
	fmt.Printf("Is correct? %v!\n", bytes.Equal(plaintext, result))
	fmt.Printf("Origin bytes:\n%x\n", string(plaintext))
	fmt.Printf("Result bytes:\n%x\n", string(result))
	fmt.Printf("Result string:\n%s", string(result))

}
