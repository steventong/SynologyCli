package dsm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const globalQuickConnectEndpoint = "https://global.quickconnect.to/Serv.php"

// ResolvedServer is the normalized DSM endpoint selected for login.
type ResolvedServer struct {
	URL          string
	QuickConnect bool
}

// ServerResolver normalizes direct addresses and resolves QuickConnect IDs.
type ServerResolver struct {
	httpClient           *http.Client
	quickConnectEndpoint string
	probeTimeout         time.Duration
}

type quickConnectRequest struct {
	ID              string `json:"id"`
	Command         string `json:"command"`
	ServerID        string `json:"serverID"`
	Version         int    `json:"version"`
	StopWhenSuccess bool   `json:"stop_when_success"`
	StopWhenError   bool   `json:"stop_when_error"`
}

type quickConnectServerInfo struct {
	Command  string                `json:"command"`
	Version  int                   `json:"version"`
	Errno    int                   `json:"errno"`
	Suberrno *int                  `json:"suberrno,omitempty"`
	Errinfo  string                `json:"errinfo,omitempty"`
	Sites    []string              `json:"sites,omitempty"`
	Server   *quickConnectServer   `json:"server,omitempty"`
	Service  *quickConnectService  `json:"service,omitempty"`
	SmartDNS *quickConnectSmartDNS `json:"smartdns,omitempty"`
}

type quickConnectServer struct {
	DDNS           string                  `json:"ddns,omitempty"`
	External       *quickConnectExternal   `json:"external,omitempty"`
	RedirectPrefix string                  `json:"redirect_prefix,omitempty"`
	Interfaces     []quickConnectInterface `json:"interface,omitempty"`
}

type quickConnectExternal struct {
	IP   string `json:"ip,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type quickConnectInterface struct {
	IP   string             `json:"ip,omitempty"`
	IPv6 []quickConnectIPv6 `json:"ipv6,omitempty"`
}

type quickConnectIPv6 struct {
	Address string `json:"address,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

type quickConnectService struct {
	Port           int    `json:"port,omitempty"`
	ExternalPort   int    `json:"ext_port,omitempty"`
	RelayDomain    string `json:"relay_dn,omitempty"`
	RelayDualStack string `json:"relay_dualstack,omitempty"`
	RelayIPv6      string `json:"relay_ipv6,omitempty"`
	RelayPort      int    `json:"relay_port,omitempty"`
	HTTPSIP        string `json:"https_ip,omitempty"`
	HTTPSPort      int    `json:"https_port,omitempty"`
}

type quickConnectSmartDNS struct {
	Host       string   `json:"host,omitempty"`
	LAN        []string `json:"lan,omitempty"`
	LANv6      []string `json:"lanv6,omitempty"`
	External   string   `json:"external,omitempty"`
	Externalv6 string   `json:"externalv6,omitempty"`
}

type quickConnectCandidate struct {
	url string
}

// NewServerResolver creates a resolver using Synology's global QuickConnect
// discovery service.
func NewServerResolver(httpClient *http.Client) *ServerResolver {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &ServerResolver{
		httpClient:           httpClient,
		quickConnectEndpoint: globalQuickConnectEndpoint,
		probeTimeout:         2 * time.Second,
	}
}

// ResolveServer accepts a full URL, a bare IP/domain, or a QuickConnect ID.
func ResolveServer(ctx context.Context, input string, useHTTPS bool, httpClient *http.Client) (ResolvedServer, error) {
	return NewServerResolver(httpClient).Resolve(ctx, input, useHTTPS)
}

// Resolve normalizes a direct server or discovers the best reachable endpoint
// for a QuickConnect ID.
func (r *ServerResolver) Resolve(ctx context.Context, input string, useHTTPS bool) (ResolvedServer, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return ResolvedServer{}, errors.New("server is required")
	}

	if !isQuickConnectID(input) {
		normalized, err := normalizeDirectServer(input, useHTTPS)
		if err != nil {
			return ResolvedServer{}, err
		}
		return ResolvedServer{URL: normalized}, nil
	}

	resolved, err := r.resolveQuickConnect(ctx, input, useHTTPS)
	if err != nil {
		return ResolvedServer{}, fmt.Errorf("resolve QuickConnect ID: %w", err)
	}
	return ResolvedServer{URL: resolved, QuickConnect: true}, nil
}

func isQuickConnectID(input string) bool {
	if strings.Contains(input, "://") || strings.ContainsAny(input, ".:/[]") {
		return false
	}
	for index, character := range input {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			(index > 0 && (character == '-' || character == '_')) {
			continue
		}
		return false
	}
	return input != ""
}

func normalizeDirectServer(input string, useHTTPS bool) (string, error) {
	hasScheme := strings.Contains(input, "://")
	if !hasScheme {
		scheme := "https"
		if !useHTTPS {
			scheme = "http"
		}
		if parsedIP := net.ParseIP(strings.Trim(input, "[]")); parsedIP != nil && strings.Contains(input, ":") {
			input = "[" + strings.Trim(input, "[]") + "]"
		}
		input = scheme + "://" + input
	}

	parsed, err := url.Parse(input)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("server URL must use http or https")
	}
	if parsed.Hostname() == "" {
		return "", errors.New("server URL must include a host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("server URL must not include a query or fragment")
	}

	if !hasScheme && parsed.Port() == "" {
		defaultPort := "5001"
		if parsed.Scheme == "http" {
			defaultPort = "5000"
		}
		parsed.Host = net.JoinHostPort(parsed.Hostname(), defaultPort)
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func (r *ServerResolver) resolveQuickConnect(ctx context.Context, quickConnectID string, useHTTPS bool) (string, error) {
	serviceEndpoint, serverInfo, err := r.queryQuickConnectServer(ctx, quickConnectID, useHTTPS)
	if err != nil {
		return "", err
	}

	if resolved := r.firstReachable(ctx, quickConnectCandidates(serverInfo, useHTTPS, false)); resolved != "" {
		return resolved, nil
	}

	tunnelInfo, err := r.invokeQuickConnect(ctx, serviceEndpoint, quickConnectID, useHTTPS, "request_tunnel")
	if err != nil {
		return "", err
	}
	if tunnelInfo.Errno != 0 {
		return "", quickConnectResponseError(tunnelInfo)
	}
	if resolved := r.firstReachable(ctx, quickConnectCandidates(tunnelInfo, useHTTPS, true)); resolved != "" {
		return resolved, nil
	}

	return "", errors.New("no reachable DSM endpoint returned by QuickConnect")
}

func (r *ServerResolver) queryQuickConnectServer(ctx context.Context, quickConnectID string, useHTTPS bool) (string, quickConnectServerInfo, error) {
	info, err := r.invokeQuickConnect(ctx, r.quickConnectEndpoint, quickConnectID, useHTTPS, "get_server_info")
	if err != nil {
		return "", quickConnectServerInfo{}, err
	}
	if info.Errno == 0 {
		return r.quickConnectEndpoint, info, nil
	}

	for _, site := range info.Sites {
		endpoint, endpointErr := quickConnectSiteEndpoint(site)
		if endpointErr != nil {
			continue
		}
		siteInfo, siteErr := r.invokeQuickConnect(ctx, endpoint, quickConnectID, useHTTPS, "get_server_info")
		if siteErr == nil && siteInfo.Errno == 0 {
			return endpoint, siteInfo, nil
		}
	}
	return "", quickConnectServerInfo{}, quickConnectResponseError(info)
}

func (r *ServerResolver) invokeQuickConnect(
	ctx context.Context,
	endpoint string,
	quickConnectID string,
	useHTTPS bool,
	command string,
) (quickConnectServerInfo, error) {
	serviceID := "dsm"
	if useHTTPS {
		serviceID = "dsm_https"
	}
	body, err := json.Marshal(quickConnectRequest{
		ID:              serviceID,
		Command:         command,
		ServerID:        quickConnectID,
		Version:         1,
		StopWhenSuccess: false,
		StopWhenError:   false,
	})
	if err != nil {
		return quickConnectServerInfo{}, fmt.Errorf("encode QuickConnect request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return quickConnectServerInfo{}, fmt.Errorf("create QuickConnect request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "synologycli/0.1")

	response, err := r.httpClient.Do(request)
	if err != nil {
		return quickConnectServerInfo{}, fmt.Errorf("send QuickConnect request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
		return quickConnectServerInfo{}, fmt.Errorf("QuickConnect returned HTTP %s", response.Status)
	}

	var info quickConnectServerInfo
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(&info); err != nil {
		return quickConnectServerInfo{}, fmt.Errorf("decode QuickConnect response: %w", err)
	}
	return info, nil
}

func (r *ServerResolver) firstReachable(ctx context.Context, candidates []quickConnectCandidate) string {
	for _, candidate := range candidates {
		probeContext, cancel := context.WithTimeout(ctx, r.probeTimeout)
		client, err := NewClient(candidate.url, r.httpClient)
		if err == nil {
			var apis map[string]apiDefinition
			apis, err = client.discoverAPIs(probeContext)
			if err == nil {
				_, hasAuth := apis["SYNO.API.Auth"]
				_, hasEncryption := apis["SYNO.API.Encryption"]
				if hasAuth && hasEncryption {
					cancel()
					return candidate.url
				}
			}
		}
		cancel()
	}
	return ""
}

func quickConnectCandidates(info quickConnectServerInfo, useHTTPS, relayOnly bool) []quickConnectCandidate {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	basePath := strings.Trim(strings.TrimSpace(valueOrEmpty(info.Server, func(server *quickConnectServer) string {
		return server.RedirectPrefix
	})), "/")

	var candidates []quickConnectCandidate
	add := func(host string, port int) {
		if candidateURL := makeQuickConnectURL(scheme, host, port, basePath); candidateURL != "" {
			candidates = append(candidates, quickConnectCandidate{url: candidateURL})
		}
	}

	if !relayOnly {
		if info.Server != nil {
			for _, networkInterface := range info.Server.Interfaces {
				add(networkInterface.IP, servicePort(info))
			}
		}
		if info.SmartDNS != nil {
			for _, host := range info.SmartDNS.LAN {
				add(host, servicePort(info))
			}
		}

		if info.Server != nil {
			for _, networkInterface := range info.Server.Interfaces {
				for _, ipv6 := range networkInterface.IPv6 {
					if isGloballyReachableIPv6(ipv6) {
						add(ipv6.Address, servicePort(info))
					}
				}
			}
		}
		if info.SmartDNS != nil {
			for _, host := range info.SmartDNS.LANv6 {
				add(host, servicePort(info))
			}
		}

		if info.Server != nil {
			for _, port := range uniquePorts(servicePort(info), externalPort(info)) {
				add(info.Server.DDNS, port)
			}
		}
		if info.SmartDNS != nil {
			for _, port := range uniquePorts(servicePort(info), externalPort(info)) {
				add(info.SmartDNS.Host, port)
			}
		}

		if info.Server != nil && info.Server.External != nil {
			for _, port := range uniquePorts(externalPort(info), servicePort(info)) {
				add(info.Server.External.IP, port)
			}
		}
		if info.SmartDNS != nil {
			for _, port := range uniquePorts(externalPort(info), servicePort(info)) {
				add(info.SmartDNS.External, port)
			}
		}
		if useHTTPS && info.Service != nil {
			add(info.Service.HTTPSIP, info.Service.HTTPSPort)
		}

		if info.Server != nil && info.Server.External != nil {
			for _, port := range uniquePorts(externalPort(info), servicePort(info)) {
				add(info.Server.External.IPv6, port)
			}
		}
		if info.SmartDNS != nil {
			for _, port := range uniquePorts(externalPort(info), servicePort(info)) {
				add(info.SmartDNS.Externalv6, port)
			}
		}
	}

	if info.Service != nil {
		add(info.Service.RelayDualStack, info.Service.RelayPort)
		add(info.Service.RelayDomain, info.Service.RelayPort)
		add(info.Service.RelayIPv6, info.Service.RelayPort)
	}
	return deduplicateQuickConnectCandidates(candidates)
}

func makeQuickConnectURL(scheme, host string, port int, basePath string) string {
	host = normalizeQuickConnectHost(host)
	if host == "" || port <= 0 {
		return ""
	}
	result := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}
	if basePath != "" {
		result.Path = "/" + basePath
	}
	return result.String()
}

func normalizeQuickConnectHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "NULL") {
		return ""
	}
	return strings.Trim(host, "[]")
}

func isGloballyReachableIPv6(ipv6 quickConnectIPv6) bool {
	if strings.EqualFold(strings.TrimSpace(ipv6.Scope), "global") {
		return true
	}
	address := strings.ToLower(strings.TrimSpace(ipv6.Address))
	return address != "" &&
		!strings.HasPrefix(address, "fe80:") &&
		!strings.HasPrefix(address, "fc") &&
		!strings.HasPrefix(address, "fd")
}

func uniquePorts(ports ...int) []int {
	seen := make(map[int]struct{})
	var result []int
	for _, port := range ports {
		if port <= 0 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	return result
}

func servicePort(info quickConnectServerInfo) int {
	if info.Service == nil {
		return 0
	}
	return info.Service.Port
}

func externalPort(info quickConnectServerInfo) int {
	if info.Service == nil {
		return 0
	}
	return info.Service.ExternalPort
}

func deduplicateQuickConnectCandidates(candidates []quickConnectCandidate) []quickConnectCandidate {
	seen := make(map[string]struct{})
	result := make([]quickConnectCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate.url]; ok {
			continue
		}
		seen[candidate.url] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func quickConnectSiteEndpoint(site string) (string, error) {
	site = strings.TrimSpace(site)
	if site == "" {
		return "", errors.New("empty QuickConnect site")
	}
	if !strings.Contains(site, "://") {
		site = "https://" + site
	}
	parsed, err := url.Parse(site)
	if err != nil || parsed.Host == "" {
		return "", errors.New("invalid QuickConnect site")
	}
	if !strings.HasSuffix(strings.TrimSuffix(parsed.Path, "/"), "/Serv.php") {
		parsed.Path = path.Join(parsed.Path, "Serv.php")
	}
	return parsed.String(), nil
}

func quickConnectResponseError(info quickConnectServerInfo) error {
	if info.Errinfo != "" {
		return fmt.Errorf("QuickConnect error %d: %s", info.Errno, info.Errinfo)
	}
	if info.Suberrno != nil {
		return fmt.Errorf("QuickConnect error %d (suberror %d)", info.Errno, *info.Suberrno)
	}
	return fmt.Errorf("QuickConnect error %d", info.Errno)
}

func valueOrEmpty[T any](value *T, getter func(*T) string) string {
	if value == nil {
		return ""
	}
	return getter(value)
}
