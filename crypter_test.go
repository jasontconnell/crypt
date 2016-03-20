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


	fmt.Println("old one", CBCDecryptOldBase64Url(key, "-qNuRpQKjGbGleL_8Efuhg=="))

	enc2 := CBCEncryptBase64Url(key, []byte("jason connell rules"))
	fmt.Println("jason connell rules", enc2)

	dec2 := CBCDecryptBase64Url(key, enc2)
	fmt.Println(enc2, dec2)		
	fmt.Println("old one with new decrypt", CBCDecryptBase64Url(key, "-qNuRpQKjGbGleL_8Efuhg=="))
}

func TestSHA256(t *testing.T){
	fmt.Println(SHA256("jason123"))
	fmt.Println(SHA256("Sublime2"))
	fmt.Println("mlee123", SHA256("mlee123"))
}

//04eCB7UgahvXP_XZ-ZMdEw==
func TestCBCDecryptOldBase64Url(t *testing.T){
		key := "random array of characters"

	fmt.Println("cbc decrypt old", CBCDecryptOldBase64Url(key, "JbQMc_vRDhKUbV3e0Jn01A=="))
	fmt.Println("cbc decrypt new", CBCDecryptBase64Url(key, "JbQMc_vRDhKUbV3e0Jn01A=="))
}