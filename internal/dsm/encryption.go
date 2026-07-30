package dsm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// EncryptionInfo is returned by SYNO.API.Encryption getinfo.
type EncryptionInfo struct {
	CipherKey   string `json:"cipherkey"`
	CipherToken string `json:"ciphertoken"`
	PublicKey   string `json:"public_key"`
	ServerTime  int64  `json:"server_time"`
}

func encryptLoginCredentials(info EncryptionInfo, username, password string, unixTime int64) (url.Values, error) {
	return encryptLoginCredentialsWithRandom(info, username, password, unixTime, rand.Reader)
}

func encryptLoginCredentialsWithRandom(info EncryptionInfo, username, password string, unixTime int64, random io.Reader) (url.Values, error) {
	if strings.TrimSpace(info.CipherKey) == "" {
		return nil, errors.New("DSM encryption response has an empty cipherkey")
	}
	if strings.TrimSpace(info.CipherToken) == "" {
		return nil, errors.New("DSM encryption response has an empty ciphertoken")
	}

	publicKey, err := parsePublicKey(info.PublicKey)
	if err != nil {
		return nil, err
	}

	credentials := url.Values{
		"account": {username},
		"passwd":  {password},
	}
	plaintext := fmt.Sprintf("%s=%d&%s", info.CipherToken, unixTime, credentials.Encode())

	ciphertext, err := rsa.EncryptPKCS1v15(random, publicKey, []byte(plaintext))
	if err != nil {
		return nil, fmt.Errorf("encrypt DSM login credentials: %w", err)
	}

	return url.Values{
		info.CipherKey: {base64.StdEncoding.EncodeToString(ciphertext)},
	}, nil
}

func parsePublicKey(encoded string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(stripASCIIWhitespace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode DSM RSA public key: %w", err)
	}

	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse DSM RSA public key: %w", err)
	}

	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("DSM public key has type %T, want RSA", key)
	}
	return publicKey, nil
}

func stripASCIIWhitespace(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		default:
			return r
		}
	}, value)
}
