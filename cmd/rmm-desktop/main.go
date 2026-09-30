//go:build windows

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows/registry"
)

func probeServer(url string, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	probeURL := strings.TrimRight(url, "/") + "/api/auth/state"
	resp, err := client.Get(probeURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

func readRegistryString(subKey, valName string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	val, _, err := k.GetStringValue(valName)
	if err != nil {
		return ""
	}
	return val
}

func readClientInfoFile() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	candidates := []string{
		filepath.Join(pd, "HomelabRMM", "client_info.json"),
		filepath.Join(pd, "HomelabRMM", "agent.json"),
	}
	for _, p := range candidates {
		if b, err := os.ReadFile(p); err == nil {
			var parsed struct {
				ServerURL string `json:"server_url"`
			}
			if json.Unmarshal(b, &parsed) == nil && parsed.ServerURL != "" {
				return parsed.ServerURL
			}
		}
	}
	return ""
}

func main() {
	modeFlag := flag.String("mode", "", "tray mode: 'agent' (client-facing software & tickets) or 'server' (admin console)")
	serverURLFlag := flag.String("server-url", "", "URL of the Homelab RMM server (default https://localhost:8443)")
	// Accepted and ignored: the portal no longer takes the device's identity
	// from the tray app (the local agent vouches for it instead).
	_ = flag.String("agent-id", "", "unused; kept so older shortcuts still start")
	debugFlag := flag.Bool("debug", false, "enable debug logging and developer tools")
	flag.Parse()

	// 1. Determine Mode
	mode := strings.ToLower(strings.TrimSpace(*modeFlag))
	if mode == "" {
		if envMode := os.Getenv("RMM_MODE"); envMode != "" {
			mode = strings.ToLower(envMode)
		} else {
			exeName := strings.ToLower(filepath.Base(os.Args[0]))
			if strings.Contains(exeName, "agent") {
				mode = "agent"
			} else if strings.Contains(exeName, "server") {
				mode = "server"
			} else {
				// Default to agent mode for desktop clients unless running on a dedicated server
				pd := os.Getenv("ProgramData")
				if pd == "" {
					pd = `C:\ProgramData`
				}
				if _, err := os.Stat(filepath.Join(pd, "HomelabRMM-Server")); err == nil {
					mode = "server"
				} else {
					mode = "agent"
				}
			}
		}
	}
	if mode != "agent" && mode != "server" {
		mode = "agent"
	}

	// 2. Discover the server URL
	serverURL := *serverURLFlag
	if serverURL == "" {
		if envURL := os.Getenv("RMM_SERVER_URL"); envURL != "" {
			serverURL = envURL
		} else if envPub := os.Getenv("RMM_PUBLIC_URL"); envPub != "" {
			serverURL = envPub
		} else if regSrv := readRegistryString(`SOFTWARE\HomelabRMM`, "ServerURL"); regSrv != "" {
			serverURL = regSrv
		} else if fileSrv := readClientInfoFile(); fileSrv != "" {
			serverURL = fileSrv
		} else {
			serverURL = "https://localhost:8443"
		}
	}

	debug := *debugFlag || os.Getenv("RMM_DEBUG") != ""

	// Ensure WebView2 ignores self-signed certificates on local instances
	existingArgs := os.Getenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS")
	if !strings.Contains(existingArgs, "--ignore-certificate-errors") {
		if existingArgs != "" {
			os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", existingArgs+" --ignore-certificate-errors")
		} else {
			os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--ignore-certificate-errors")
		}
	}

	// Store WebView2 cache and profile in %LOCALAPPDATA%\HomelabRMM\WebView2
	var webviewDataDir string
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		folderName := "HomelabRMM-Agent"
		if mode == "server" {
			folderName = "HomelabRMM-Server"
		}
		webviewDataDir = filepath.Join(localAppData, folderName, "WebView2")
		_ = os.MkdirAll(webviewDataDir, 0o750)
	}

	winTitle := "Homelab Support & Software"
	if mode == "server" {
		winTitle = "Homelab RMM Server Console"
	}

	wv := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     debug,
		DataPath:  webviewDataDir,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  winTitle,
			Width:  1280,
			Height: 820,
			Center: true,
		},
	})
	if wv == nil {
		fmt.Fprintln(os.Stderr, "failed to initialize WebView2 window")
		os.Exit(1)
	}

	setupTray(wv, mode, serverURL)

	// Bind helper RPCs for offline/reconnect handling
	_ = wv.Bind("probeServer", func(url string) bool {
		return probeServer(url, 1500*time.Millisecond)
	})
	_ = wv.Bind("navigateTo", func(url string) {
		if mode == "agent" {
			// The portal needs a fresh pass whichever page asked.
			openPortal("software", false)
			return
		}
		wv.Dispatch(func() {
			wv.Navigate(url)
		})
	})
	_ = wv.Bind("openPortal", func() {
		openPortal("software", false)
	})

	switch {
	case !probeServer(serverURL, 1*time.Second):
		wv.SetHtml(renderOfflinePage(serverURL))
	case mode == "agent":
		openPortal("software", false)
	default:
		wv.Navigate(serverURL)
	}

	wv.Run()
	removeTrayIcon()
	wv.Destroy()
}
