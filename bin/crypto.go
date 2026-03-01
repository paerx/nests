package bin

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/hkdf"

	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
)

type PlainEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type signData struct {
	EKey   string `json:"e_key"`
	EValue string `json:"e_value"`
}

func DecryptConfig(cfg Config, globalKey string) ([]PlainEntry, error) {
	return decryptConfig(cfg, globalKey, true)
}

func DecryptConfigNoVerify(cfg Config, globalKey string) ([]PlainEntry, error) {
	return decryptConfig(cfg, globalKey, false)
}

func DecryptConfigWithEnvKey(cfg Config, envKeyBase64 string) ([]PlainEntry, error) {
	key, err := decodeBase64(envKeyBase64)
	if err != nil {
		return nil, err
	}
	return decryptConfigWithKey(cfg, key)
}

func decryptConfig(cfg Config, globalKey string, verify bool) ([]PlainEntry, error) {
	key, err := deriveEnvKey(globalKey, cfg.KdfSalt, cfg.Name)
	if err != nil {
		return nil, err
	}
	return decryptConfigWithKeyAndVerify(cfg, key, verify)
}

func decryptConfigWithKey(cfg Config, key []byte) ([]PlainEntry, error) {
	return decryptConfigWithKeyAndVerify(cfg, key, false)
}

func decryptConfigWithKeyAndVerify(cfg Config, key []byte, verify bool) ([]PlainEntry, error) {
	if verify {
		compact := make([]signData, 0, len(cfg.EDatas))
		for _, e := range cfg.EDatas {
			compact = append(compact, signData{EKey: e.EKey, EValue: e.EValue})
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(compact); err != nil {
			return nil, err
		}
		payload := bytes.TrimSpace(buf.Bytes())
		mac := hmac.New(sm3.New, key)
		_, _ = mac.Write(payload)
		sign := hex.EncodeToString(mac.Sum(nil))
		if sign != cfg.Sign {
			return nil, errors.New("signature mismatch")
		}
	}

	plain := make([]PlainEntry, 0, len(cfg.EDatas))
	for _, e := range cfg.EDatas {
		var k string
		var err error
		if verify {
			k, err = decryptValueStrict(e.EKey, key)
		} else {
			k, err = decryptValueLenient(e.EKey, key)
		}
		if err != nil {
			return nil, err
		}
		var v string
		if verify {
			v, err = decryptValueStrict(e.EValue, key)
		} else {
			v, err = decryptValueLenient(e.EValue, key)
		}
		if err != nil {
			return nil, err
		}
		plain = append(plain, PlainEntry{Key: k, Value: v})
	}
	return plain, nil
}

func deriveEnvKey(globalKey, salt, name string) ([]byte, error) {
	saltBytes := []byte(salt)
	if dec, err := base64.StdEncoding.DecodeString(salt); err == nil {
		saltBytes = dec
	}
	reader := hkdf.New(sm3.New, []byte(globalKey), saltBytes, []byte(name))
	key := make([]byte, 16)
	if _, err := reader.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func decryptValueStrict(encoded string, key []byte) (string, error) {
	data, err := decodeBase64(encoded)
	if err != nil {
		return "", err
	}
	if len(data) < 16 {
		return "", errors.New("ciphertext too short")
	}
	iv := data[:16]
	ciphertext := data[16:]
	block, err := sm4.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return "", errors.New("ciphertext invalid")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plain := make([]byte, len(ciphertext))
	mode.CryptBlocks(plain, ciphertext)
	plain, err = pkcs7Unpad(plain, block.BlockSize())
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func decryptValueLenient(encoded string, key []byte) (string, error) {
	data, err := decodeBase64(encoded)
	if err != nil {
		return "", err
	}
	if len(data) < 16 {
		return "", errors.New("ciphertext too short")
	}
	iv := data[:16]
	ciphertext := data[16:]
	block, err := sm4.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return "", errors.New("ciphertext invalid")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plain := make([]byte, len(ciphertext))
	mode.CryptBlocks(plain, ciphertext)
	if out, err := pkcs7Unpad(plain, block.BlockSize()); err == nil {
		return string(out), nil
	}
	return string(plain), nil
}

func decodeBase64(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("empty ciphertext")
	}
	if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(encoded)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padding")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if data[i] != byte(pad) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}
