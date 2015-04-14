package crypt

import (
	"testing"
	"fmt"
)

func TestEncrypt(t *testing.T){
	key := "random array of characters"

	s := Encrypt(key, []byte("jason123"))

	t.Log(s)
	fmt.Println(s)
}

func TestDecrypt(t *testing.T){
	key := "random array of characters"

	s := Decrypt(key, "dkYsRBDNTMujVjmSy59NiJjhg9bSpPtN")

	fmt.Println(s)
	t.Log(s)
}

