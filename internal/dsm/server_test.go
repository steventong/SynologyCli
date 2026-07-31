package dsm

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestServerResolverNormalizesDirectAddresses(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		useHTTPS    bool
		want        string
		wantIsQuick bool
	}{
		{
			name:     "complete URL",
			input:    "https://nas.example.com:7443/",
			useHTTPS: true,
			want:     "https://nas.example.com:7443",
		},
		{
			name:     "bare IPv4",
			input:    "192.168.1.10",
			useHTTPS: true,
			want:     "https://192.168.1.10:5001",
		},
		{
			name:     "bare domain with explicit port",
			input:    "nas.example.com:8443",
			useHTTPS: true,
			want:     "https://nas.example.com:8443",
		},
		{
			name:     "bare domain using HTTP",
			input:    "nas.example.com",
			useHTTPS: false,
			want:     "http://nas.example.com:5000",
		},
		{
			name:     "bare IPv6",
			input:    "2001:db8::1",
			useHTTPS: true,
			want:     "https://[2001:db8::1]:5001",
		},
	}

	resolver := NewServerResolver(nil)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolver.Resolve(context.Background(), test.input, test.useHTTPS)
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if got.URL != test.want {
				t.Errorf("URL = %q, want %q", got.URL, test.want)
			}
			if got.QuickConnect != test.wantIsQuick {
				t.Errorf("QuickConnect = %v, want %v", got.QuickConnect, test.wantIsQuick)
			}
		})
	}
}

func TestIsQuickConnectID(t *testing.T) {
	tests := map[string]bool{
		"my-nas":                     true,
		"NAS_01":                     true,
		"https://nas.example.com":    false,
		"nas.example.com":            false,
		"192.168.1.10":               false,
		"192.168.1.10:5001":          false,
		"2001:db8::1":                false,
		"":                           false,
		"-invalid-leading-character": false,
	}

	for input, want := range tests {
		if got := isQuickConnectID(input); got != want {
			t.Errorf("isQuickConnectID(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestServerResolverResolvesQuickConnectID(t *testing.T) {
	dsmServer := newQuickConnectTestDSMServer(t)
	defer dsmServer.Close()
	dsmURL, err := url.Parse(dsmServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	dsmHost, dsmPort := splitTestServerHost(t, dsmURL)

	var received quickConnectRequest
	quickConnectServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/Serv.php" {
			http.NotFound(writer, request)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Errorf("decode QuickConnect request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writeJSON(t, writer, quickConnectServerInfo{
			Command: received.Command,
			Version: 1,
			Errno:   0,
			Server: &quickConnectServer{
				External: &quickConnectExternal{IP: dsmHost},
			},
			Service: &quickConnectService{
				Port:         dsmPort,
				ExternalPort: dsmPort,
			},
		})
	}))
	defer quickConnectServer.Close()

	resolver := NewServerResolver(quickConnectServer.Client())
	resolver.quickConnectEndpoint = quickConnectServer.URL + "/Serv.php"
	resolver.probeTimeout = time.Second

	got, err := resolver.Resolve(context.Background(), "example-qc-id", false)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.URL != dsmServer.URL {
		t.Errorf("URL = %q, want %q", got.URL, dsmServer.URL)
	}
	if !got.QuickConnect {
		t.Error("QuickConnect = false, want true")
	}
	wantRequest := quickConnectRequest{
		ID:              "dsm",
		Command:         "get_server_info",
		ServerID:        "example-qc-id",
		Version:         1,
		StopWhenSuccess: false,
		StopWhenError:   false,
	}
	if !reflect.DeepEqual(received, wantRequest) {
		t.Errorf("QuickConnect request = %+v, want %+v", received, wantRequest)
	}
}

func TestServerResolverRequestsTunnelWhenDirectConnectionsFail(t *testing.T) {
	dsmServer := newQuickConnectTestDSMServer(t)
	defer dsmServer.Close()
	dsmURL, err := url.Parse(dsmServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	dsmHost, dsmPort := splitTestServerHost(t, dsmURL)

	var mu sync.Mutex
	var commands []string
	quickConnectServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var received quickConnectRequest
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Errorf("decode QuickConnect request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		commands = append(commands, received.Command)
		mu.Unlock()

		info := quickConnectServerInfo{
			Command: received.Command,
			Version: 1,
			Errno:   0,
		}
		if received.Command == "request_tunnel" {
			info.Service = &quickConnectService{
				RelayDomain: dsmHost,
				RelayPort:   dsmPort,
			}
		}
		writeJSON(t, writer, info)
	}))
	defer quickConnectServer.Close()

	resolver := NewServerResolver(quickConnectServer.Client())
	resolver.quickConnectEndpoint = quickConnectServer.URL
	resolver.probeTimeout = time.Second

	got, err := resolver.Resolve(context.Background(), "relay-only-id", false)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.URL != dsmServer.URL {
		t.Errorf("URL = %q, want %q", got.URL, dsmServer.URL)
	}

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"get_server_info", "request_tunnel"}; !reflect.DeepEqual(commands, want) {
		t.Errorf("commands = %v, want %v", commands, want)
	}
}

func newQuickConnectTestDSMServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/webapi/query.cgi" {
			http.NotFound(writer, request)
			return
		}
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
					"maxVersion": 6,
					"path":       "auth.cgi",
				},
			},
		})
	}))
}

func splitTestServerHost(t *testing.T, serverURL *url.URL) (string, int) {
	t.Helper()
	host, portString, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
