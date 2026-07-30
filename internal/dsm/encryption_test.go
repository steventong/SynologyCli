package dsm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strconv"
	"testing"
)

func TestEncryptLoginCredentials(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	info := EncryptionInfo{
		CipherKey:   "dynamic_cipher",
		CipherToken: "dynamic_token",
		PublicKey:   base64.StdEncoding.EncodeToString(publicDER),
	}
	const timestamp int64 = 1_722_222_222
	const username = "测试 user&admin"
	const password = "p+a ss&word=✓"

	form, err := encryptLoginCredentials(info, username, password, timestamp)
	if err != nil {
		t.Fatalf("encryptLoginCredentials() error = %v", err)
	}
	if form.Has("account") || form.Has("passwd") {
		t.Fatalf("encrypted form leaked plaintext credential keys: %v", form)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(form.Get(info.CipherKey))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := rsa.DecryptPKCS1v15(nil, privateKey, ciphertext)
	if err != nil {
		t.Fatalf("decrypt ciphertext: %v", err)
	}

	values, err := url.ParseQuery(string(plaintext))
	if err != nil {
		t.Fatalf("parse decrypted form: %v", err)
	}
	if got := values.Get(info.CipherToken); got != strconv.FormatInt(timestamp, 10) {
		t.Errorf("token timestamp = %q, want %d", got, timestamp)
	}
	if got := values.Get("account"); got != username {
		t.Errorf("account = %q, want %q", got, username)
	}
	if got := values.Get("passwd"); got != password {
		t.Errorf("passwd = %q, want %q", got, password)
	}
}

func TestEncryptLoginCredentialsRejectsInvalidPublicKey(t *testing.T) {
	info := EncryptionInfo{
		CipherKey:   "cipher",
		CipherToken: "token",
		PublicKey:   "not-base64",
	}

	form, err := encryptLoginCredentials(info, "user", "secret", 123)
	if err == nil {
		t.Fatalf("encryptLoginCredentials() form = %v, want error", form)
	}
}
