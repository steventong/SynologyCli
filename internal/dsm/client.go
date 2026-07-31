package dsm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 2 << 20

var (
	// ErrOTPRequired indicates that DSM accepted the password authentication
	// request but requires a one-time password to continue.
	ErrOTPRequired = errors.New("DSM requires a one-time password")

	// ErrOTPInvalid indicates that DSM rejected the supplied one-time password.
	ErrOTPInvalid = errors.New("DSM rejected the one-time password")
)

// Client implements the DSM API discovery and encrypted authentication flow.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	now        func() time.Time
}

// LoginRequest contains the user-controlled inputs for SYNO.API.Auth login.
type LoginRequest struct {
	Username string
	Password string
	OTPCode  string
	Session  string
}

// LoginResult contains the session identifiers returned by DSM.
type LoginResult struct {
	SID          string `json:"sid"`
	DID          string `json:"did,omitempty"`
	IsPortalPort bool   `json:"is_portal_port,omitempty"`
}

type apiDefinition struct {
	MinVersion int    `json:"minVersion"`
	MaxVersion int    `json:"maxVersion"`
	Path       string `json:"path"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

func (e apiError) Error() string {
	switch e.Code {
	case 403:
		return "DSM requires a one-time password (API error 403)"
	case 404:
		return "DSM rejected the one-time password (API error 404)"
	}
	if e.Message == "" {
		return fmt.Sprintf("DSM API error %d", e.Code)
	}
	return fmt.Sprintf("DSM API error %d: %s", e.Code, e.Message)
}

func (e apiError) Unwrap() error {
	switch e.Code {
	case 403:
		return ErrOTPRequired
	case 404:
		return ErrOTPInvalid
	default:
		return nil
	}
}

type responseEnvelope[T any] struct {
	Success bool      `json:"success"`
	Data    T         `json:"data"`
	Error   *apiError `json:"error,omitempty"`
}

// NewClient creates a DSM client rooted at server, for example
// https://nas.example.com:5001.
func NewClient(server string, httpClient *http.Client) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(server))
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, errors.New("server URL must use http or https")
	}
	if baseURL.Host == "" {
		return nil, errors.New("server URL must include a host")
	}
	if baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("server URL must not include a query or fragment")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
		now:        time.Now,
	}, nil
}

// EncryptedLogin discovers DSM API paths, fetches a one-time RSA public key,
// encrypts account and passwd together, and then calls SYNO.API.Auth login.
//
// It intentionally has no plaintext fallback. If encryption setup fails, no
// authentication request is sent.
func (c *Client) EncryptedLogin(ctx context.Context, request LoginRequest) (LoginResult, error) {
	if request.Username == "" {
		return LoginResult{}, errors.New("username is required")
	}
	if request.Password == "" {
		return LoginResult{}, errors.New("password is required")
	}
	if request.Session == "" {
		request.Session = "AudioStation"
	}

	apis, err := c.discoverAPIs(ctx)
	if err != nil {
		return LoginResult{}, fmt.Errorf("discover DSM APIs: %w", err)
	}

	encryptionAPI, ok := apis["SYNO.API.Encryption"]
	if !ok {
		return LoginResult{}, errors.New("DSM does not advertise SYNO.API.Encryption")
	}
	authAPI, ok := apis["SYNO.API.Auth"]
	if !ok {
		return LoginResult{}, errors.New("DSM does not advertise SYNO.API.Auth")
	}

	encryptionInfo, err := c.fetchEncryptionInfo(ctx, encryptionAPI)
	if err != nil {
		return LoginResult{}, fmt.Errorf("fetch DSM encryption info: %w", err)
	}

	clockOffset := encryptionInfo.ServerTime - c.now().Unix()
	encrypted, err := encryptLoginCredentials(
		encryptionInfo,
		request.Username,
		request.Password,
		c.now().Unix()+clockOffset,
	)
	if err != nil {
		return LoginResult{}, err
	}

	if request.OTPCode != "" {
		encrypted.Set("otp_code", request.OTPCode)
		encrypted.Set("enable_device_token", "yes")
	}
	encrypted.Set("session", request.Session)
	encrypted.Set("format", "sid")
	encrypted.Set("client_time", strconv.FormatInt(c.now().Unix(), 10))

	var response responseEnvelope[LoginResult]
	if err := c.postAPI(
		ctx,
		authAPI.Path,
		"SYNO.API.Auth",
		"login",
		selectAuthVersion(authAPI),
		encrypted,
		&response,
	); err != nil {
		return LoginResult{}, err
	}
	if err := validateEnvelope(response.Success, response.Error); err != nil {
		return LoginResult{}, err
	}
	if response.Data.SID == "" {
		return LoginResult{}, errors.New("DSM login succeeded without returning a SID")
	}
	return response.Data, nil
}

func (c *Client) discoverAPIs(ctx context.Context) (map[string]apiDefinition, error) {
	form := url.Values{"query": {"all"}}
	var response responseEnvelope[map[string]apiDefinition]
	if err := c.postAPI(ctx, "query.cgi", "SYNO.API.Info", "query", 1, form, &response); err != nil {
		return nil, err
	}
	if err := validateEnvelope(response.Success, response.Error); err != nil {
		return nil, err
	}
	return response.Data, nil
}

func (c *Client) fetchEncryptionInfo(ctx context.Context, api apiDefinition) (EncryptionInfo, error) {
	var response responseEnvelope[EncryptionInfo]
	if err := c.postAPI(
		ctx,
		api.Path,
		"SYNO.API.Encryption",
		"getinfo",
		selectVersionOne(api),
		nil,
		&response,
	); err != nil {
		return EncryptionInfo{}, err
	}
	if err := validateEnvelope(response.Success, response.Error); err != nil {
		return EncryptionInfo{}, err
	}
	return response.Data, nil
}

func (c *Client) postAPI(ctx context.Context, apiPath, apiName, method string, version int, form url.Values, destination any) error {
	if form == nil {
		form = make(url.Values)
	}
	form.Set("api", apiName)
	form.Set("method", method)
	form.Set("version", strconv.Itoa(version))

	endpoint := c.webAPIURL(apiPath)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create %s request: %w", apiName, err)
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("User-Agent", "synologycli/0.1")

	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("send %s request: %w", apiName, err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
		return fmt.Errorf("%s returned HTTP %s", apiName, response.Status)
	}

	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s response: %w", apiName, err)
	}
	return nil
}

func (c *Client) webAPIURL(apiPath string) *url.URL {
	result := *c.baseURL
	cleanAPIPath := strings.TrimPrefix(apiPath, "/")
	if strings.HasPrefix(cleanAPIPath, "webapi/") {
		result.Path = path.Join(c.baseURL.Path, cleanAPIPath)
	} else {
		result.Path = path.Join(c.baseURL.Path, "webapi", cleanAPIPath)
	}
	result.RawPath = ""
	return &result
}

func validateEnvelope(success bool, apiErr *apiError) error {
	if success {
		return nil
	}
	if apiErr != nil {
		return *apiErr
	}
	return errors.New("DSM API returned success=false without an error")
}

func selectVersionOne(api apiDefinition) int {
	if api.MinVersion <= 1 && api.MaxVersion >= 1 {
		return 1
	}
	return api.MinVersion
}

func selectAuthVersion(api apiDefinition) int {
	for _, candidate := range []int{6, 5, 4, 1} {
		if candidate >= api.MinVersion && candidate <= api.MaxVersion {
			return candidate
		}
	}
	return api.MaxVersion
}
