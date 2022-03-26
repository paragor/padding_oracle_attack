package helper

import "fmt"

func SplitData(data []byte, maxChunkSize int) ([][]byte, error) {
	buffer := make([]byte, len(data))
	copy(buffer, data)
	if maxChunkSize <= 0 {
		return [][]byte{}, fmt.Errorf("maxChunkSize should be > 0")
	}

	result := [][]byte{}
	cur := 0
	for i := maxChunkSize; i <= len(data); i += maxChunkSize {
		result = append(result, buffer[cur:i])
		cur = i
	}

	if cur < len(data) {
		result = append(result, buffer[cur:len(data)])
	}

	return result, nil
}
