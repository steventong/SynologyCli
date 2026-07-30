package dsm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestEncryptedLoginEndToEnd(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	const (
		cipherKey   = "dynamic_cipher"
		cipherToken = "dynamic_token"
		serverTime  = int64(1_800_000_120)
		clientTime  = int64(1_800_000_000)
		username    = "alice@example.com"
		password    = "correct horse & battery=staple"
		otp         = "123456"
	)

	var loginCalls atomic.Int32
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/webapi/query.cgi":
			assertFormValue(t, request.Form, "api", "SYNO.API.Info")
			assertFormValue(t, request.Form, "method", "query")
			assertFormValue(t, request.Form, "query", "all")
			writeJSON(t, writer, map[string]any{
				"success": true,
				"data": map[string]any{
					"SYNO.API.Encryption": map[string]any{
						"minVersion": 1,
						"maxVersion": 1,
						"path":       "encryption.cgi",
					},
					"SYNO.API.Auth": map[string]any{
						"minVersion": 1,
						"maxVersion": 7,
						"path":       "auth.cgi",
					},
				},
			})

		case "/webapi/encryption.cgi":
			assertFormValue(t, request.Form, "api", "SYNO.API.Encryption")
			assertFormValue(t, request.Form, "method", "getinfo")
			writeJSON(t, writer, map[string]any{
				"success": true,
				"data": map[string]any{
					"cipherkey":   cipherKey,
					"ciphertoken": cipherToken,
					"public_key":  base64.StdEncoding.EncodeToString(publicDER),
					"server_time": serverTime,
				},
			})

		case "/webapi/auth.cgi":
			loginCalls.Add(1)
			assertFormValue(t, request.Form, "api", "SYNO.API.Auth")
			assertFormValue(t, request.Form, "method", "login")
			assertFormValue(t, request.Form, "version", "6")
			assertFormValue(t, request.Form, "session", "AudioStation")
			assertFormValue(t, request.Form, "format", "sid")
			assertFormValue(t, request.Form, "client_time", strconv.FormatInt(clientTime, 10))
			assertFormValue(t, request.Form, "otp_code", otp)
			assertFormValue(t, request.Form, "enable_device_token", "yes")
			if request.Form.Has("account") || request.Form.Has("passwd") {
				t.Errorf("auth request leaked plaintext credential fields: %v", request.Form)
			}

			ciphertext, decodeErr := base64.StdEncoding.DecodeString(request.Form.Get(cipherKey))
			if decodeErr != nil {
				t.Errorf("decode ciphertext: %v", decodeErr)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			plaintext, decryptErr := rsa.DecryptPKCS1v15(nil, privateKey, ciphertext)
			if decryptErr != nil {
				t.Errorf("decrypt ciphertext: %v", decryptErr)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			decrypted, parseErr := url.ParseQuery(string(plaintext))
			if parseErr != nil {
				t.Errorf("parse decrypted credentials: %v", parseErr)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			assertFormValue(t, decrypted, cipherToken, strconv.FormatInt(serverTime, 10))
			assertFormValue(t, decrypted, "account", username)
			assertFormValue(t, decrypted, "passwd", password)

			writeJSON(t, writer, map[string]any{
				"success": true,
				"data": map[string]any{
					"sid": "test-session-id",
					"did": "test-device-id",
				},
			})

		default:
			http.NotFound(writer, request)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(clientTime, 0) }

	result, err := client.EncryptedLogin(context.Background(), LoginRequest{
		Username: username,
		Password: password,
		OTPCode:  otp,
		Session:  "AudioStation",
	})
	if err != nil {
		t.Fatalf("EncryptedLogin() error = %v", err)
	}
	if result.SID != "test-session-id" || result.DID != "test-device-id" {
		t.Errorf("EncryptedLogin() result = %+v", result)
	}
	if got := loginCalls.Load(); got != 1 {
		t.Errorf("auth login calls = %d, want 1", got)
	}
}

func TestEncryptedLoginDoesNotFallBackToPlaintext(t *testing.T) {
	var loginCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/webapi/query.cgi":
			writeJSON(t, writer, map[string]any{
				"success": true,
				"data": map[string]any{
					"SYNO.API.Encryption": map[string]any{"minVersion": 1, "maxVersion": 1, "path": "encryption.cgi"},
					"SYNO.API.Auth":       map[string]any{"minVersion": 1, "maxVersion": 6, "path": "auth.cgi"},
				},
			})
		case "/webapi/encryption.cgi":
			writeJSON(t, writer, map[string]any{
				"success": true,
				"data": map[string]any{
					"cipherkey":   "cipher",
					"ciphertoken": "token",
					"public_key":  "invalid",
					"server_time": 123,
				},
			})
		case "/webapi/auth.cgi":
			loginCalls.Add(1)
			t.Error("plaintext fallback sent an authentication request")
			writer.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.EncryptedLogin(context.Background(), LoginRequest{
		Username: "user",
		Password: "password",
	})
	if err == nil {
		t.Fatal("EncryptedLogin() error = nil, want public-key error")
	}
	if got := loginCalls.Load(); got != 0 {
		t.Errorf("auth login calls = %d, want 0", got)
	}
}

func assertFormValue(t *testing.T, values url.Values, key, want string) {
	t.Helper()
	if got := values.Get(key); got != want {
		t.Errorf("form[%q] = %q, want %q", key, got, want)
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
