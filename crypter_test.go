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
}

func TestCBCDecrypt(t *testing.T){
	key := "random array of characters"
	//s := Decrypt(key, "hg+TLS1yFfXaGaW3t7Cc0Q==")

	t.Log("aFsycP-HU62YL8yLXRC5lw==", CBCDecrypt(key, "aFsycP+HU62YL8yLXRC5lw=="))
	//t.Log("Lj9w6mPQNKEE5KSA9KeAXtRCA99WAGOkBRfm", Decrypt(key, "Lj9w6mPQNKEE5KSA9KeAXtRCA99WAGOkBRfm"))
	t.Log("-qNuRpQKjGbGleL_8Efuhg==", CBCDecrypt(key, "+qNuRpQKjGbGleL/8Efuhg=="))
}

func TestCBCEncrypt(t *testing.T){
	key := "random array of characters"
	enc := CBCEncrypt(key, []byte("jason is awesome"))
	dec := CBCDecrypt(key, enc)

	fmt.Println(enc)
	fmt.Println(dec)
}

func TestCBCEncryptBase64Url(t *testing.T){
	key := "random array of characters"
	enc := CBCEncryptBase64Url(key, []byte("jason is awesome"))
	dec := CBCDecryptBase64Url(key, enc)

	fmt.Println(enc)
	fmt.Println(dec)

}