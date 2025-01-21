package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

func Encrypt(key string, text []byte) (string, error) {
	bkey := evpBytesToKey(key, 32)
	block, err := aes.NewCipher(bkey)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return encodeBase64(ciphertext), nil

}

func Decrypt(key, b64 string) (string, error) {
	bkey := evpBytesToKey(key, 32)
	text, err := decodeBase64(b64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(bkey)
	if err != nil {
		return "", err
	}
	if len(text) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return string(text), nil
}

func CBCEncrypt(key string, text []byte) (string, error) {
	bkey := evpBytesToKey(key, 32)
	block, err := aes.NewCipher(bkey)
	if err != nil {
		return "", err
	}

	addPadding(&text)
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], text)
	return encodeBase64(ciphertext), nil
}

func CBCDecrypt(key, b64 string) (string, error) {
	hashKey := evpBytesToKey(key, 32)
	block, err := aes.NewCipher(hashKey)
	if err != nil {
		return "", err
	}

	b, err := decodeBase64(b64)
	if err != nil {
		return "", err
	}

	if len(b) < block.BlockSize() {
		return "", fmt.Errorf("cipher text too short %d", len(b))
	}

	iv := b[:aes.BlockSize]
	b = b[aes.BlockSize:]

	if len(b)%block.BlockSize() != 0 {
		return "", fmt.Errorf("cipher text is not a multiple of block size %d %d", len(b), block.BlockSize())
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(b, b)
	s := string(removePadding(b))
	return s, nil // now clear text
}

func CBCDecryptBase64Url(key, b64 string) (string, error) {
	t := base64urldecode(b64)
	return CBCDecrypt(key, t)
}

func CBCEncryptBase64Url(key string, text []byte) (string, error) {
	t, err := CBCEncrypt(key, text)
	if err != nil {
		return "", err
	}
	return base64urlencode(t), nil
}

func SHA256(s string) string {
	bytes := sha256sum([]byte(s))
	return encodeBase64(bytes)
}

func sha256sum(d []byte) []byte {
	h := sha256.New()
	h.Write(d)
	return h.Sum(nil)
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)

	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}

func addPadding(b *[]byte) {
	l := len(*b)
	m := l % 16
	if m == 0 {
		return
	}

	n := 16 - m
	bytes := make([]byte, n)
	for i := 0; i < n; i++ {
		bytes[i] = byte(n)
	}

	*b = append(*b, bytes...)
}

func removePadding(b []byte) []byte {
	l := len(b)
	if l == 0 {
		return b
	}
	p := int(b[l-1])
	var ret []byte
	if p <= 16 {
		ret = b[:(l - p)]
	} else {
		ret = b
	}

	return ret
}

func base64urlencode(b64 string) string {
	t := strings.Replace(b64, "+", "-", -1)
	t = strings.Replace(t, "/", "_", -1)
	return t
}

func base64urldecode(b64 string) string {
	t := strings.Replace(b64, "-", "+", -1)
	t = strings.Replace(t, "_", "/", -1)
	return t
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	return data, err
}
