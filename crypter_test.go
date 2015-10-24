package crypt

import (
	"testing"
	"fmt"
)

func TestEncrypt(t *testing.T){
	key := "random array of characters"

	s := Encrypt(key, []byte("abopassword"))

	t.Log("Encrypted abopassword")
	t.Log(s)
	fmt.Println(s)
}

func TestDecrypt(t *testing.T){
	key := "random array of characters"

	//s := Decrypt(key, "hg+TLS1yFfXaGaW3t7Cc0Q==")

	t.Log("aFsycP-HU62YL8yLXRC5lw==", Decrypt(key, "aFsycP+HU62YL8yLXRC5lw=="))
	t.Log("Lj9w6mPQNKEE5KSA9KeAXtRCA99WAGOkBRfm", Decrypt(key, "Lj9w6mPQNKEE5KSA9KeAXtRCA99WAGOkBRfm"))
	t.Log("-qNuRpQKjGbGleL_8Efuhg==", Decrypt(key, "+qNuRpQKjGbGleL/8Efuhg=="))
}

