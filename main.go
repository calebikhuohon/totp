package main

import (
	"crypto/sha512"
	"fmt"

	"github.com/sec51/twofactor"
)

func main() {
	otp, err := twofactor.NewTOTP("calebikhuohon@gmail.comHENNGECHALLENGE003", "", sha512.New, 10)
	if err != nil {
		return err
	}

	fmt.Println(otp)
}