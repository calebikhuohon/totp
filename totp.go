package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"time"
)


// hmac_sha provides the crypto algorithm.
// it computes a Hashed Message Authentication Code with the
// crypto hash algorithm as a parameter
func hmacSha(h func() hash.Hash, key []byte, text []byte) []byte {
	mac := hmac.New(h, key)
	mac.Write(text)
	return mac.Sum(nil)
}

// hexStr2Bytes converts a HEX string to []byte
func hexStr2Bytes(s string) []byte {
	data, err := hex.DecodeString(s)

	if err != nil {
		panic(err)
	}
	return data
}

// generateTOTP generates a TOTP value for the given set of
// parameters.
func generateTOTP(key string, timeStr string, returnDigits int, crypto func() hash.Hash) string {
	var result string

	//using the counter. First 8 bytes are for the moving factor
	//complaint with base RFC 4226 (HOTP)
	for len(timeStr) < 16 {
		timeStr = "0" + timeStr
	}

	// Get the HEX in a byte
	msg := hexStr2Bytes(timeStr)
	k := hexStr2Bytes(key)

	h := hmacSha(crypto, k, msg)

	//put selected bytes into result int
	offset := h[len(h)-1] & 0xf

	b := (uint64(h[offset])&0x7f)<<24 |
		(uint64(h[offset+1])&0xff)<<16 |
		(uint64(h[offset+2])&0xff)<<8 |
		(uint64(h[offset+3]) & 0xff)

	otp := int64(b) % int64(math.Pow10(returnDigits))

	fmt.Sprintf("%d", otp)

	result = fmt.Sprintf("%d", otp)

	for len(result) < returnDigits {
		result = "0" + result
	}
	return result

}

func secret(key string) string {
	return hex.EncodeToString([]byte(key))
}

func main() {
	var t0 int64 = 0
	var x int64 = 30
	steps := "0"

	var te int64 = time.Now().Unix()
	t := (te - t0) / x

	fmt.Println(t)
	steps = fmt.Sprintf("%X", t)

	fmt.Println(steps)
	for len(steps) < 16 {
		steps = "0" + steps
	}

	seed := secret("your_secret")
	s := generateTOTP(seed, steps, 10, sha512.New)

	fmt.Println(s)
}
