package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/md5"
    "crypto/sha256"
	"encoding/base64"
	"io"
    "hash"
    "strings"
)

func Encrypt(key string, text []byte) string {
    bkey := evpBytesToKey(key,32)
    block, err := aes.NewCipher(bkey)
    if err != nil {
        panic(err)
    }
    ciphertext := make([]byte, aes.BlockSize+len(text))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        panic(err)
    }
    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
    return encodeBase64(ciphertext)

}

func Decrypt(key, b64 string) string {
    bkey := evpBytesToKey(key,32)
    text := decodeBase64(b64)
    block, err := aes.NewCipher(bkey)
    if err != nil {
        panic(err)
    }
    if len(text) < aes.BlockSize {
        panic("ciphertext too short")
    }

    iv := text[:aes.BlockSize]
    text = text[aes.BlockSize:]

    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(text, text)
    return string(text)
}

func CBCEncrypt(key string, text []byte) string {
    bkey := evpBytesToKey(key,32)
    block, err := aes.NewCipher(bkey)
    if err != nil {
        panic(err)
    }

    addPadding(&text)
    ciphertext := make([]byte, aes.BlockSize+len(text))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        panic(err)
    }
    cbc := cipher.NewCBCEncrypter(block, iv)
    cbc.CryptBlocks(ciphertext[aes.BlockSize:], text)
    return encodeBase64(ciphertext)
}

func CBCDecrypt(key, b64 string) string {
    b := decodeBase64(b64)  
    hashKey := evpBytesToKey(key,32)
    iv := b[:aes.BlockSize]
    b = b[aes.BlockSize:]
    block, err := aes.NewCipher(hashKey)

    if err != nil {
        panic(err)
    }

    cbc := cipher.NewCBCDecrypter(block, iv)
    cbc.CryptBlocks(b, b)
    s := string(removePadding(b))
    return s // now clear text
}

func CBCDecryptOld(key, b64 string) string {
    b := decodeBase64(b64)  
    hashKey,iv := genIvAndKey([]byte{}, []byte(key), md5.New(), 32, 1)
    block, err := aes.NewCipher(hashKey)

    if err != nil {
        panic(err)
    }

    cbc := cipher.NewCBCDecrypter(block, iv)
    cbc.CryptBlocks(b, b)
    s := string(removePadding(b))
    return s // now clear text
}

func CBCDecryptBase64Url(key, b64 string) string {
    t := base64urldecode(b64)
    return CBCDecrypt(key, t)
}

func CBCDecryptOldBase64Url(key, b64 string) string {
    t := base64urldecode(b64)
    return CBCDecryptOld(key, t)
}

func CBCEncryptBase64Url(key string, text []byte) string {
    t := CBCEncrypt(key, text)
    return base64urlencode(t)
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
    key = make([]byte, keyLen)

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
    if m == 0 { return }

    n := 16 - m
    bytes := make([]byte, n)
    for i := 0; i < n; i++ {
        bytes[i] = byte(n)
    }

    *b = append(*b, bytes...)
}

func removePadding(b []byte) []byte {
    l := len(b)
    if l == 0 { return b }
    p := int(b[l-1])
    var ret []byte
    if p <= 16 {
        ret = b[:(l-p)]
    } else {
        ret = b
    }

    return ret
}

func genIvAndKey(salt, keyData []byte, h hash.Hash, keyLen, blockLen int) (key []byte, iv []byte) {
    res := make([]byte, 0, keyLen+blockLen)
    p := append(keyData, salt...)
    var d_last []byte

    for ; len(res) < keyLen+blockLen; h.Reset() {
        h.Write(append(d_last, p...))
        resNew := h.Sum(res)
        d_last = resNew[len(res):]
        res = resNew
    }

    return res[:keyLen], res[keyLen:]
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

func decodeBase64(s string) []byte {                                                                                                                                                                        
    data, err := base64.StdEncoding.DecodeString(s)                                                                                                                                                         
    if err != nil { panic(err) }                                                                                                                                                                            
    return data                                                                                                                                                                                             
}                