package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

// ==========================================
// Configuration Structs
// ==========================================

type Config struct {
	Log          LogConfig           `json:"log"`
	DNS          *DNSConfig          `json:"dns,omitempty"`
	Inbounds     []Inbound           `json:"inbounds,omitempty"`
	Outbounds    []Outbound          `json:"outbounds"`
	Route        *RouteConfig        `json:"route,omitempty"`
	Experimental *ExperimentalConfig `json:"experimental,omitempty"`
}

type LogConfig struct {
	Level     string `json:"level"`
	Output    string `json:"output,omitempty"`
	Timestamp bool   `json:"timestamp"`
}

type DNSConfig struct {
	Servers []DNSServer `json:"servers"`
	Rules   []DNSRule   `json:"rules,omitempty"`
	Final   string      `json:"final,omitempty"`
}

type DNSServer struct {
	Tag             string `json:"tag"`
	Type            string `json:"type,omitempty"`
	Server          string `json:"server,omitempty"`
	Address         string `json:"address,omitempty"`
	AddressResolver string `json:"address_resolver,omitempty"`
	Detour          string `json:"detour,omitempty"`
	Path            string `json:"path,omitempty"`
}

type DNSRule struct {
	ClashMode string `json:"clash_mode,omitempty"`
	Server    string `json:"server"`
}

type Inbound struct {
	Type          string      `json:"type"`
	Tag           string      `json:"tag"`
	Listen        string      `json:"listen,omitempty"`
	ListenPort    int         `json:"listen_port,omitempty"`
	UpMbps        int         `json:"up_mbps,omitempty"`
	DownMbps      int         `json:"down_mbps,omitempty"`
	Users         []User      `json:"users,omitempty"`
	TLS           *TLSConfig  `json:"tls,omitempty"`
	Obfs          *ObfsConfig `json:"obfs,omitempty"`
	Masquerade    *MasqConfig `json:"masquerade,omitempty"`
	InterfaceName string      `json:"interface_name,omitempty"`
	Address       []string    `json:"address,omitempty"`
	Stack         string      `json:"stack,omitempty"`
	AutoRoute     bool        `json:"auto_route,omitempty"`
	StrictRoute   bool        `json:"strict_route,omitempty"`
	Sniff         bool        `json:"sniff,omitempty"`
}

type Outbound struct {
	Type       string      `json:"type"`
	Tag        string      `json:"tag"`
	Server     string      `json:"server,omitempty"`
	ServerPort int         `json:"server_port,omitempty"`
	Password   string      `json:"password,omitempty"`
	UpMbps     int         `json:"up_mbps,omitempty"`
	DownMbps   int         `json:"down_mbps,omitempty"`
	TLS        *TLSConfig  `json:"tls,omitempty"`
	Obfs       *ObfsConfig `json:"obfs,omitempty"`
}

type TLSConfig struct {
	Enabled         bool   `json:"enabled"`
	Insecure        bool   `json:"insecure,omitempty"`
	ServerName      string `json:"server_name,omitempty"`
	CertificatePath string `json:"certificate_path,omitempty"`
	KeyPath         string `json:"key_path,omitempty"`
}

type ObfsConfig struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type MasqConfig struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	RewriteHost bool   `json:"rewrite_host"`
}

type User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type RouteConfig struct {
	Rules                 []RouteRule `json:"rules"`
	DefaultDomainResolver string      `json:"default_domain_resolver,omitempty"`
	AutoDetectInterface   bool        `json:"auto_detect_interface"`
}

type RouteRule struct {
	Protocol  string `json:"protocol,omitempty"`
	Action    string `json:"action,omitempty"`
	ClashMode string `json:"clash_mode,omitempty"`
	Outbound  string `json:"outbound,omitempty"`
}

type ExperimentalConfig struct {
	CacheFile CacheFileConfig `json:"cache_file"`
	ClashAPI  ClashAPIConfig  `json:"clash_api"`
}

type CacheFileConfig struct {
	Enabled bool `json:"enabled"`
}

type ClashAPIConfig struct {
	ExtController       string `json:"external_controller"`
	ExtUI               string `json:"external_ui,omitempty"`
	ExtUIDownloadURL    string `json:"external_ui_download_url,omitempty"`
	ExtUIDownloadDetour string `json:"external_ui_download_detour,omitempty"`
	DefaultMode         string `json:"default_mode,omitempty"`
	Secret              string `json:"secret,omitempty"`
}

// Struct for Persistence
type Preferences struct {
	IPv4Type  string `json:"ipv4_type"`
	IPv6Type  string `json:"ipv6_type"`
	DNSMode   string `json:"dns_mode"`
	DNSRemote string `json:"dns_remote"`
	DNSLocal  string `json:"dns_local"`
}

// ==========================================
// WARP Structs
// ==========================================

const CFWarpRegURL = "https://api.cloudflareclient.com/v0a2025/reg"

type cfRegisterRequest struct {
	TOS string `json:"tos"`
	Key string `json:"key"`
}

type cfRegisterResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

type WarpResponse struct {
	ClientID string
	V4       string
	V6       string
	PubKey   string // Server Public Key
	PrivKey  string // Client Private Key
}

// ==========================================
// Globals
// ==========================================

var (
	BaseDir   = filepath.Join(os.Getenv("HOME"), ".singassist", "hysteria2")
	PrefsFile = filepath.Join(os.Getenv("HOME"), ".singassist", "prefs.json")
	Colors    = map[string]string{
		"Red": "\033[31m", "Green": "\033[32m", "Yellow": "\033[33m", "Cyan": "\033[36m", "Reset": "\033[0m",
	}
)

func main() {
	checkDeps()
	for {
		clearScreen()
		fmt.Println(Colors["Green"] + "Sing-Box Hysteria2 Manager" + Colors["Reset"])
		fmt.Println("1. Create New Instance")
		fmt.Println("2. View Existing Configs")
		fmt.Println("3. Exit")
		fmt.Print("\nOption: ")

		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			createInstance(reader)
		case "2":
			viewConfigs(reader)
		case "3":
			os.Exit(0)
		}
	}
}

// ==========================================
// Core: Create
// ==========================================

func createInstance(r *bufio.Reader) {
	rawID := prompt(r, "Enter unique ID (e.g. gaming): ", "")
	id := sanitizeID(rawID)

	if id == "" {
		fmt.Println(Colors["Red"] + "ID cannot be empty!" + Colors["Reset"])
		return
	}
	if id != rawID {
		fmt.Printf(Colors["Yellow"]+"Sanitized ID to: %s%s\n", id, Colors["Reset"])
	}

	instanceDir := filepath.Join(BaseDir, id)
	if _, err := os.Stat(instanceDir); !os.IsNotExist(err) {
		if prompt(r, "ID exists. Overwrite? [y/N]: ", "N") != "y" {
			return
		}
		os.RemoveAll(instanceDir)
	}
	os.MkdirAll(instanceDir, 0755)

	// Port
	portStr := prompt(r, "Listen Port (Enter for random): ", "")
	port := randomInt(10000, 60000)
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}

	// IPs
	ipv4 := selectIPv4(r)
	ipv6 := selectIPv6(r)

	// DNS
	dnsMode, remoteDNS, localDNS := selectDNS(r)

	// Auth
	password := prompt(r, "Auth Password (Enter to auto-gen): ", generateHex(16))
	obfsPass := prompt(r, "Obfs Password (Enter to auto-gen): ", generateHex(8))
	sni := prompt(r, "SNI Domain [www.bing.com]: ", "www.bing.com")
	sni = strings.TrimSpace(sni)

	// Bandwidth
	up, _ := strconv.Atoi(prompt(r, "Upload Mbps [100]: ", "100"))
	down, _ := strconv.Atoi(prompt(r, "Download Mbps [100]: ", "100"))

	// --- FEATURE: Mixed Inbound ---
	enableMixed := prompt(r, "Enable Mixed (HTTP/SOCKS) Inbound? [y/N]: ", "N") == "y"
	mixedPort := 2080
	mixedIP := "127.0.0.1"
	if enableMixed {
		mixedIP = prompt(r, "  Mixed Listen IP [127.0.0.1]: ", "127.0.0.1")
		mPortStr := prompt(r, "  Mixed Port [2080]: ", "2080")
		mp, err := strconv.Atoi(mPortStr)
		if err == nil {
			mixedPort = mp
		}
	}

	// --- FEATURE: Clash API & Metacube ---
	enableClash := prompt(r, "Enable Clash API? [y/N]: ", "N") == "y"
	clashPort := 9090
	clashIP := "127.0.0.1"
	clashSecret := ""
	enableMetacube := false

	if enableClash {
		clashIP = prompt(r, "  Clash API Listen IP [127.0.0.1]: ", "127.0.0.1")
		cPortStr := prompt(r, "  Clash API Port [9090]: ", "9090")
		cp, err := strconv.Atoi(cPortStr)
		if err == nil {
			clashPort = cp
		}
		clashSecret = prompt(r, "  Clash API Secret (Enter to auto-gen): ", generateHex(16))
		enableMetacube = prompt(r, "  Download Metacube Dashboard? [y/N]: ", "N") == "y"
	}

	// --- FEATURE: WARP Outbound ---
	enableWarp := prompt(r, "Use WARP (Cloudflare WireGuard) as outbound? [y/N]: ", "N") == "y"
	var warpConfig WarpResponse
	if enableWarp {
		fmt.Println(Colors["Yellow"] + "Fetching WARP config..." + Colors["Reset"])
		var warpErr error
		warpConfig, warpErr = fetchWarpConfig()
		if warpErr != nil {
			fmt.Printf(Colors["Red"]+"WARP setup failed: %v\nFalling back to direct."+Colors["Reset"]+"\n", warpErr)
			enableWarp = false
		} else {
			fmt.Println(Colors["Green"] + "WARP registered successfully!" + Colors["Reset"])
		}
	}

	// Certs
	fmt.Println(Colors["Yellow"] + "Generating Certificates..." + Colors["Reset"])
	certPath := filepath.Join(instanceDir, "server.crt")
	keyPath := filepath.Join(instanceDir, "server.key")
	generateSelfSignedCert(sni, certPath, keyPath)

	// 1. Server Config
	// Build server outbounds
	var serverOutbounds []interface{}
	if enableWarp {
		wgOutbound := buildWireGuardOutbound(warpConfig)
		serverOutbounds = append(serverOutbounds, wgOutbound)
	}
	serverOutbounds = append(serverOutbounds, map[string]string{"type": "direct", "tag": "direct"})

	serverConfigMap := map[string]interface{}{
		"log": LogConfig{Level: "info", Output: filepath.Join(instanceDir, "access.log"), Timestamp: true},
		"inbounds": []Inbound{{
			Type: "hysteria2", Tag: "hy2-" + id, Listen: "::", ListenPort: port,
			UpMbps: up, DownMbps: down,
			Users:      []User{{Name: "user", Password: password}},
			TLS:        &TLSConfig{Enabled: true, CertificatePath: certPath, KeyPath: keyPath},
			Obfs:       &ObfsConfig{Type: "salamander", Password: obfsPass},
			Masquerade: &MasqConfig{Type: "proxy", URL: "https://" + sni + "/", RewriteHost: true},
		}},
		"outbounds": serverOutbounds,
	}
	writeJSON(filepath.Join(instanceDir, "config.json"), serverConfigMap)

	// 2. Client Config Generator
	genClient := func(serverIP, suffix string) {
		// Base Inbounds (TUN)
		inbounds := []Inbound{
			{
				Type:          "tun",
				Tag:           "tun-in",
				InterfaceName: "tun0",
				Address:       []string{"172.19.0.1/30"},
				Stack:         "gvisor",
				AutoRoute:     true,
				StrictRoute:   true,
				Sniff:         true,
			},
		}

		// Conditional Mixed Inbound
		if enableMixed {
			inbounds = append(inbounds, Inbound{
				Type:       "mixed",
				Tag:        "mixed-in",
				Listen:     mixedIP,
				ListenPort: mixedPort,
				Sniff:      true,
			})
		}

		// Conditional Experimental (Clash)
		var experimental *ExperimentalConfig
		if enableClash {
			clashConfig := ClashAPIConfig{
				ExtController: clashIP + ":" + strconv.Itoa(clashPort),
				DefaultMode:   "global",
				Secret:        clashSecret,
			}
			if enableMetacube {
				clashConfig.ExtUI = "ui"
				clashConfig.ExtUIDownloadURL = "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip"
				clashConfig.ExtUIDownloadDetour = "hysteria-out"
			}
			experimental = &ExperimentalConfig{
				ClashAPI: clashConfig,
				CacheFile: CacheFileConfig{
					Enabled: true,
				},
			}
		}

		clientConf := Config{
			Log:      LogConfig{Level: "info", Timestamp: true},
			Inbounds: inbounds,
			Outbounds: []Outbound{
				{
					Type:       "hysteria2",
					Tag:        "hysteria-out",
					Server:     serverIP,
					ServerPort: port,
					Password:   password,
					UpMbps:     up,
					DownMbps:   down,
					TLS:        &TLSConfig{Enabled: true, Insecure: true, ServerName: sni},
					Obfs:       &ObfsConfig{Type: "salamander", Password: obfsPass},
				},
				{Type: "direct", Tag: "direct"},
			},
			Route: &RouteConfig{
				Rules: []RouteRule{
					{ClashMode: "direct", Outbound: "direct"},
					{ClashMode: "global", Outbound: "hysteria-out"},
				},
				DefaultDomainResolver: "local",
				AutoDetectInterface:   true,
			},
			Experimental: experimental,
		}

		// DNS Logic
		if dnsMode != "system" {
			clientConf.Route.Rules = append([]RouteRule{{Protocol: "dns", Action: "hijack-dns"}}, clientConf.Route.Rules...)
			remDNS := parseDNSURL(remoteDNS, "remote")
			remDNS.Detour = "hysteria-out"
			locDNS := parseDNSURL(localDNS, "local")

			clientConf.DNS = &DNSConfig{
				Servers: []DNSServer{remDNS, locDNS},
				Rules:   []DNSRule{{ClashMode: "global", Server: "remote"}, {ClashMode: "direct", Server: "local"}},
				Final:   "remote",
			}
		}
		writeJSON(filepath.Join(instanceDir, fmt.Sprintf("client-%s.json", suffix)), clientConf)
	}

	if ipv4 != "" {
		genClient(ipv4, "v4")
	}
	if ipv6 != "" {
		genClient(ipv6, "v6")
	}

	// Run
	setupCron(filepath.Join(instanceDir, "config.json"), filepath.Join(instanceDir, "access.log"))

	// Show Info
	displayInfo(id, ipv4, ipv6, port, password, obfsPass, sni, up, down)

	// Extra info for new features
	if enableMixed {
		fmt.Printf(Colors["Cyan"]+"Mixed Proxy Enabled: %s:%d\n"+Colors["Reset"], mixedIP, mixedPort)
	}
	if enableClash {
		fmt.Printf(Colors["Cyan"]+"Clash API Enabled:   %s:%d\n"+Colors["Reset"], clashIP, clashPort)
		fmt.Printf(Colors["Cyan"]+"Clash Secret:        %s\n"+Colors["Reset"], clashSecret)
	}
	if enableWarp {
		fmt.Printf(Colors["Cyan"] + "WARP Enabled:        Yes (WireGuard outbound)\n" + Colors["Reset"])
	}
	fmt.Println("\nPress Enter to return...")
	r.ReadString('\n')
}

// ==========================================
// Core: View Configs
// ==========================================

func viewConfigs(r *bufio.Reader) {
	files, _ := filepath.Glob(filepath.Join(BaseDir, "*"))
	if len(files) == 0 {
		fmt.Println("No configs found.")
		return
	}

	var validDirs []string
	for _, f := range files {
		if info, err := os.Stat(f); err == nil && info.IsDir() {
			fmt.Printf("[%d] %s\n", len(validDirs), filepath.Base(f))
			validDirs = append(validDirs, f)
		}
	}

	idxStr := prompt(r, "Select config: ", "0")
	idx, _ := strconv.Atoi(idxStr)
	if idx >= len(validDirs) {
		return
	}
	dir := validDirs[idx]

	// 1. Read Server Config
	var serverCfg Config
	if !readJSON(filepath.Join(dir, "config.json"), &serverCfg) {
		return
	}
	if len(serverCfg.Inbounds) == 0 {
		return
	}
	ib := serverCfg.Inbounds[0]

	// Server info extraction
	port := ib.ListenPort
	pass := ""
	if len(ib.Users) > 0 {
		pass = ib.Users[0].Password
	}
	obfs := ""
	if ib.Obfs != nil {
		obfs = ib.Obfs.Password
	}
	sni := ""
	if ib.Masquerade != nil {
		u := ib.Masquerade.URL
		u = strings.TrimPrefix(u, "https://")
		u = strings.TrimPrefix(u, "http://")
		sni = strings.Split(u, "/")[0]
	}

	// 2. Read Client IPs & Extra Features
	ipv4 := ""
	ipv6 := ""

	// We use client-v4 for feature detection as well
	var clientV4 Config
	readJSON(filepath.Join(dir, "client-v4.json"), &clientV4)
	if len(clientV4.Outbounds) > 0 {
		ipv4 = clientV4.Outbounds[0].Server
	}

	var clientV6 Config
	if readJSON(filepath.Join(dir, "client-v6.json"), &clientV6) {
		if len(clientV6.Outbounds) > 0 {
			ipv6 = clientV6.Outbounds[0].Server
		}
	}

	// Display Core Info
	displayInfo(filepath.Base(dir), ipv4, ipv6, port, pass, obfs, sni, ib.UpMbps, ib.DownMbps)

	// Display New Features Info (Found in Client Config)
	fmt.Println(Colors["Yellow"] + "--- Extra Features (from Client Config) ---" + Colors["Reset"])

	// Check Mixed
	mixedFound := false
	for _, in := range clientV4.Inbounds {
		if in.Type == "mixed" {
			mixedFound = true
			fmt.Printf("Mixed Proxy:    %s:%d\n", in.Listen, in.ListenPort)
		}
	}
	if !mixedFound {
		fmt.Println("Mixed Proxy:    Disabled")
	}

	// Check Clash
	if clientV4.Experimental != nil && clientV4.Experimental.ClashAPI.ExtController != "" {
		c := clientV4.Experimental.ClashAPI
		fmt.Printf("Clash API:      %s\n", c.ExtController)
		if c.Secret != "" {
			fmt.Printf("Clash Secret:   %s\n", c.Secret)
		} else {
			fmt.Printf("Clash Secret:   (None)\n")
		}
		if c.ExtUIDownloadURL != "" {
			fmt.Printf("Metacube URL:   %s\n", c.ExtUIDownloadURL)
		}
	} else {
		fmt.Println("Clash API:      Disabled")
	}
	fmt.Println("")
	r.ReadString('\n')
}

// ==========================================
// Helpers: IP Selection & Persistence
// ==========================================

func sanitizeID(id string) string {
	reg, err := regexp.Compile("[^a-zA-Z0-9-_]+")
	if err != nil {
		return id
	}
	return reg.ReplaceAllString(id, "")
}

func loadPrefs() Preferences {
	var p Preferences
	if f, err := os.Open(PrefsFile); err == nil {
		defer f.Close()
		json.NewDecoder(f).Decode(&p)
	}
	return p
}

func savePrefs(p Preferences) {
	os.MkdirAll(filepath.Dir(PrefsFile), 0755)
	if f, err := os.Create(PrefsFile); err == nil {
		defer f.Close()
		e := json.NewEncoder(f)
		e.SetIndent("", "  ")
		e.Encode(p)
	}
}

func getPublicIP(version int) string {
	networkType := "tcp4"
	urls := []string{"https://api.ip.sb/ip", "https://api.ipify.org"}
	if version == 6 {
		networkType = "tcp6"
		urls = []string{"https://api6.ipify.org", "https://v6.ident.me"}
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", "1.1.1.1:53")
			},
		},
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, networkType, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	for _, u := range urls {
		resp, err := client.Get(u)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			ip := strings.TrimSpace(string(body))
			if ip != "" {
				return ip
			}
		}
	}
	return ""
}

func selectIPv4(r *bufio.Reader) string {
	prefs := loadPrefs()
	wan := getPublicIP(4)
	fmt.Println("\n--- IPv4 Selection ---")

	var ips []string
	var labels []string

	if wan != "" {
		ips = append(ips, wan)
		labels = append(labels, "WAN")
	} else {
		ips = append(ips, "MANUAL")
		labels = append(labels, "Manual Entry")
	}

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				ipStr := ipnet.IP.String()
				ips = append(ips, ipStr)
				labels = append(labels, fmt.Sprintf("%s (%s)", i.Name, ipStr))
			}
		}
	}

	defaultIdx := 0
	for i, ip := range ips {
		if ip == prefs.IPv4Type || (prefs.IPv4Type == "wan" && labels[i] == "WAN") || (prefs.IPv4Type == "manual" && ips[i] == "MANUAL") {
			defaultIdx = i
		}
	}

	for i, label := range labels {
		marker := " "
		if i == defaultIdx {
			marker = "*"
		}
		fmt.Printf("[%d]%s %s\n", i, marker, label)
	}

	selStr := prompt(r, fmt.Sprintf("Select [%d]: ", defaultIdx), strconv.Itoa(defaultIdx))
	sel, err := strconv.Atoi(selStr)
	if err != nil || sel < 0 || sel >= len(ips) {
		sel = defaultIdx
	}

	selectedIP := ips[sel]

	var saveValue string
	if selectedIP == "MANUAL" {
		saveValue = "manual"
	} else if labels[sel] == "WAN" {
		saveValue = "wan"
	} else {
		saveValue = selectedIP
	}

	if saveValue != prefs.IPv4Type {
		q := prompt(r, "Save as default IPv4 preference? [Y/n]: ", "Y")
		if strings.ToLower(q) == "y" {
			prefs.IPv4Type = saveValue
			savePrefs(prefs)
		}
	}

	if selectedIP == "MANUAL" {
		return prompt(r, "Enter IPv4: ", "")
	}
	return selectedIP
}

func selectIPv6(r *bufio.Reader) string {
	prefs := loadPrefs()
	wan := getPublicIP(6)
	fmt.Println("\n--- IPv6 Selection ---")

	var ips []string
	var labels []string

	ips = append(ips, "NONE")
	labels = append(labels, "None")

	if wan != "" {
		ips = append(ips, wan)
		labels = append(labels, "WAN")
	} else {
		ips = append(ips, "MANUAL")
		labels = append(labels, "Manual Entry")
	}

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() == nil {
				ipStr := ipnet.IP.String()
				ips = append(ips, ipStr)
				labels = append(labels, fmt.Sprintf("%s (%s)", i.Name, ipStr))
			}
		}
	}

	defaultIdx := 0
	for i, ip := range ips {
		if ip == prefs.IPv6Type || (prefs.IPv6Type == "wan" && labels[i] == "WAN") || (prefs.IPv6Type == "none" && ip == "NONE") {
			defaultIdx = i
		}
	}

	for i, label := range labels {
		marker := " "
		if i == defaultIdx {
			marker = "*"
		}
		fmt.Printf("[%d]%s %s\n", i, marker, label)
	}

	selStr := prompt(r, fmt.Sprintf("Select [%d]: ", defaultIdx), strconv.Itoa(defaultIdx))
	sel, err := strconv.Atoi(selStr)
	if err != nil || sel < 0 || sel >= len(ips) {
		sel = defaultIdx
	}

	selectedIP := ips[sel]

	var saveValue string
	if selectedIP == "NONE" {
		saveValue = "none"
	} else if selectedIP == "MANUAL" {
		saveValue = "manual"
	} else if labels[sel] == "WAN" {
		saveValue = "wan"
	} else {
		saveValue = selectedIP
	}

	if saveValue != prefs.IPv6Type {
		q := prompt(r, "Save as default IPv6 preference? [Y/n]: ", "Y")
		if strings.ToLower(q) == "y" {
			prefs.IPv6Type = saveValue
			savePrefs(prefs)
		}
	}

	if selectedIP == "NONE" {
		return ""
	}
	if selectedIP == "MANUAL" {
		return prompt(r, "Enter IPv6: ", "")
	}
	return selectedIP
}

func selectDNS(r *bufio.Reader) (mode, remote, local string) {
	prefs := loadPrefs()
	fmt.Println("\n--- DNS Strategy ---")

	defIdx := "1"
	if prefs.DNSMode == "manual" {
		defIdx = "2"
	}
	if prefs.DNSMode == "system" {
		defIdx = "3"
	}

	fmt.Printf("[1]%s Auto (Cloudflare H3)\n", condStr(defIdx == "1", "*", " "))
	fmt.Printf("[2]%s Manual\n", condStr(defIdx == "2", "*", " "))
	fmt.Printf("[3]%s System (Disable DNS Hijack)\n", condStr(defIdx == "3", "*", " "))

	opt := prompt(r, fmt.Sprintf("Select [%s]: ", defIdx), defIdx)

	if opt == "2" {
		defRemote := "tls://8.8.8.8"
		if prefs.DNSRemote != "" {
			defRemote = prefs.DNSRemote
		}
		defLocal := "local"
		if prefs.DNSLocal != "" {
			defLocal = prefs.DNSLocal
		}

		remote = prompt(r, fmt.Sprintf("Remote DNS [%s]: ", defRemote), defRemote)
		local = prompt(r, fmt.Sprintf("Local DNS [%s]: ", defLocal), defLocal)

		prefs.DNSMode = "manual"
		prefs.DNSRemote = remote
		prefs.DNSLocal = local
		savePrefs(prefs)

		return "manual", remote, local
	} else if opt == "3" {
		prefs.DNSMode = "system"
		savePrefs(prefs)
		return "system", "", ""
	}

	prefs.DNSMode = "auto"
	savePrefs(prefs)
	return "auto", "h3://1.1.1.1/dns-query", "local"
}

func condStr(cond bool, t, f string) string {
	if cond {
		return t
	}
	return f
}

func parseDNSURL(raw, tag string) DNSServer {
	if raw == "local" {
		return DNSServer{Tag: tag, Type: "local"}
	}

	ds := DNSServer{Tag: tag}
	if strings.HasPrefix(raw, "tls://") {
		ds.Type = "tls"
		ds.Server = strings.TrimPrefix(raw, "tls://")
	} else if strings.HasPrefix(raw, "h3://") {
		ds.Type = "h3"
		parts := strings.Split(strings.TrimPrefix(raw, "h3://"), "/")
		ds.Server = parts[0]
		if len(parts) > 1 {
			ds.Path = "/" + strings.Join(parts[1:], "/")
		}
	} else if strings.HasPrefix(raw, "https://") {
		ds.Type = "https"
		parts := strings.Split(strings.TrimPrefix(raw, "https://"), "/")
		ds.Server = parts[0]
		if len(parts) > 1 {
			ds.Path = "/" + strings.Join(parts[1:], "/")
		}
	} else if strings.HasPrefix(raw, "udp://") {
		ds.Type = "udp"
		ds.Server = strings.TrimPrefix(raw, "udp://")
	} else {
		ds.Type = "udp"
		ds.Server = raw
	}
	return ds
}

func displayInfo(id, v4, v6 string, port int, pass, obfs, sni string, up, down int) {
	fmt.Printf("\n%s=== Config: %s ===%s\n", Colors["Green"], id, Colors["Reset"])
	fmt.Printf("Port: %d | Brutal: %d/%d Mbps\n", port, up, down)

	params := fmt.Sprintf("?insecure=1&sni=%s&obfs=salamander&obfs-password=%s&upmbps=%d&downmbps=%d",
		sni, obfs, up, down)

	if v4 != "" {
		uri := fmt.Sprintf("hysteria2://%s@%s:%d%s#%s-v4", pass, v4, port, params, id)
		fmt.Printf("\nIPv4 URI:\n%s%s%s\n", Colors["Cyan"], uri, Colors["Reset"])
		genQR(uri)
	}
	if v6 != "" {
		uri := fmt.Sprintf("hysteria2://%s@[%s]:%d%s#%s-v6", pass, v6, port, params, id)
		fmt.Printf("\nIPv6 URI:\n%s%s%s\n", Colors["Cyan"], uri, Colors["Reset"])
		genQR(uri)
	}
}

// ------------------------------------------
// QR & Utils
// ------------------------------------------
func genQR(content string) {
	qr, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		fmt.Println("Error generating QR:", err)
		return
	}
	fmt.Print(qr.ToSmallString(false))
}

func readJSON(path string, v interface{}) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(v) == nil
}

func checkDeps() {
	if _, err := exec.LookPath("sing-box"); err != nil {
		fmt.Println(Colors["Red"] + "Error: sing-box not found." + Colors["Reset"])
		os.Exit(1)
	}
}
func prompt(r *bufio.Reader, text, def string) string {
	fmt.Print(text)
	in, _ := r.ReadString('\n')
	in = strings.TrimSpace(in)
	if in == "" {
		return def
	}
	return in
}
func randomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return int(n.Int64()) + min
}
func generateHex(n int) string {
	b := make([]byte, n/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}
func writeJSON(path string, v interface{}) {
	f, _ := os.Create(path)
	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	e.Encode(v)
}
func clearScreen() { fmt.Print("\033[H\033[2J") }
func generateSelfSignedCert(host, certPath, keyPath string) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, NotBefore: time.Now(), NotAfter: time.Now().Add(3650 * 24 * time.Hour), DNSNames: []string{host}}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	c, _ := os.Create(certPath)
	pem.Encode(c, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	c.Close()
	k, _ := os.Create(keyPath)
	pem.Encode(k, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	k.Close()
}
func setupCron(configPath, logPath string) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		return
	}
	cmdStr := fmt.Sprintf("@reboot nohup %s run -c %s >> %s 2>&1 &", bin, configPath, logPath)
	currentCron, _ := exec.Command("crontab", "-l").Output()
	if strings.Contains(string(currentCron), configPath) {
		return
	}
	newCron := string(currentCron) + "\n" + cmdStr + "\n"
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)
	cmd.Run()
	exec.Command("nohup", bin, "run", "-c", configPath).Start()
}

// ==========================================
// WARP Functions
// ==========================================

func generateWarpKeys() (privKey, pubKey string, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pub := priv.PublicKey()
	privKey = base64.StdEncoding.EncodeToString(priv.Bytes())
	pubKey = base64.StdEncoding.EncodeToString(pub.Bytes())
	return privKey, pubKey, nil
}

func fetchWarpConfig() (WarpResponse, error) {
	privKey, pubKey, err := generateWarpKeys()
	if err != nil {
		return WarpResponse{}, fmt.Errorf("key generation failed: %v", err)
	}

	tos := time.Now().Format(time.RFC3339)
	reqPayload := cfRegisterRequest{TOS: tos, Key: pubKey}
	jsonPayload, err := json.Marshal(reqPayload)
	if err != nil {
		return WarpResponse{}, fmt.Errorf("payload marshal failed: %v", err)
	}

	req, err := http.NewRequest("POST", CFWarpRegURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return WarpResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return WarpResponse{}, fmt.Errorf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return WarpResponse{}, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var cfResp cfRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return WarpResponse{}, fmt.Errorf("failed to decode response: %v", err)
	}

	if len(cfResp.Config.Peers) == 0 {
		return WarpResponse{}, fmt.Errorf("no peers in WARP response")
	}

	return WarpResponse{
		ClientID: cfResp.Config.ClientID,
		V4:       cfResp.Config.Interface.Addresses.V4,
		V6:       cfResp.Config.Interface.Addresses.V6,
		PubKey:   cfResp.Config.Peers[0].PublicKey,
		PrivKey:  privKey,
	}, nil
}

func decodeClientID(clientID string) []int {
	decoded, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		return []int{0, 0, 0}
	}
	reserved := make([]int, len(decoded))
	for i, b := range decoded {
		reserved[i] = int(b)
	}
	return reserved
}

func buildWireGuardOutbound(warp WarpResponse) map[string]interface{} {
	// Resolve WARP endpoint
	ips, err := net.LookupIP("engage.cloudflareclient.com")
	endpoint := "162.159.193.1" // fallback
	if err == nil && len(ips) > 0 {
		endpoint = ips[0].String()
	}

	reserved := decodeClientID(warp.ClientID)

	return map[string]interface{}{
		"type":          "wireguard",
		"tag":           "warp-out",
		"local_address": []string{warp.V4 + "/32", warp.V6 + "/128"},
		"private_key":   warp.PrivKey,
		"peers": []map[string]interface{}{
			{
				"server":      endpoint,
				"server_port": 2408,
				"public_key":  warp.PubKey,
				"allowed_ips": []string{"0.0.0.0/0", "::/0"},
				"reserved":    reserved,
			},
		},
		"mtu": 1280,
	}
}
