package helper

import "fmt"

func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("length of byte slices is not equivalent: %d != %d", len(a), len(b))
	}

	buf := make([]byte, len(a))

	for i := range a {
		buf[i] = a[i] ^ b[i]
	}

	return buf, nil
}

func XORBytesLoop(little, big []byte) ([]byte, error) {
	// big больше little всегда
	if len(little) > len(big) {
		return nil, fmt.Errorf("cant xor: little should be > big")
	}
	buf := make([]byte, len(big))

	j := 0
	for i := range big {
		buf[i] = big[i] ^ little[j]
		j++
		if j >= len(little) {
			j = 0
		}
	}

	return buf, nil
}
