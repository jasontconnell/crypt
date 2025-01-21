package crypt

import (
	"testing"
)

func TestCBCDecryptInvalid(t *testing.T) {
	key := "random array of characters"
	enc, err := Encrypt(key, []byte("secret password of a random length"))
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}

	t.Log("got encrypted", enc)
	invalid := enc[:len(enc)-1]
	dec, err := CBCDecrypt(key, invalid)
	if err != nil {
		t.Log(err)
	} else {
		t.Fail()
	}
	t.Log(dec)
}

func TestEncrypt(t *testing.T) {
	key := "random array of characters"

	s, err := Encrypt(key, []byte("abopassword"))
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}

	t.Log("Encrypted abopassword")
	t.Log(s)
}

func TestCBCDecrypt(t *testing.T) {
	key := "random array of characters"
	//s := Decrypt(key, "hg+TLS1yFfXaGaW3t7Cc0Q==")

	s, err := CBCDecrypt(key, "aFsycP+HU62YL8yLXRC5lw==")
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	t.Log("aFsycP-HU62YL8yLXRC5lw==", s)

	s2, err := CBCDecrypt(key, "+qNuRpQKjGbGleL/8Efuhg==")
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	t.Log("-qNuRpQKjGbGleL_8Efuhg==", s2)
}

func TestCBCEncrypt(t *testing.T) {
	key := "random array of characters"
	enc, err := CBCEncrypt(key, []byte("jason is awesome"))
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	dec, err := CBCDecrypt(key, enc)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	t.Log(enc)
	t.Log(dec)

}

func TestCBCEncryptBase64Url(t *testing.T) {
	key := "random array of characters"
	enc, err := CBCEncryptBase64Url(key, []byte("jason is awesome"))
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	dec, err := CBCDecryptBase64Url(key, enc)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	t.Log(enc)
	t.Log(dec)

	enc2, err := CBCEncryptBase64Url(key, []byte("jason connell rules"))
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	t.Log("jason connell rules", enc2)

	dec2, err := CBCDecryptBase64Url(key, enc2)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	t.Log(enc2, dec2)
}

func TestSHA256(t *testing.T) {
	t.Log(SHA256("jason123"))
	t.Log(SHA256("Sublime2"))
	t.Log("mlee123", SHA256("mlee123"))
}

// 04eCB7UgahvXP
