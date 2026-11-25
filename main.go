package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	protocolVersion = 1
	maxFrameSize    = 32 << 20
)

type message struct {
	Type     string          `json:"type"`
	Version  int             `json:"version,omitempty"`
	Role     string          `json:"role,omitempty"`
	Name     string          `json:"name,omitempty"`
	Hostname string          `json:"hostname,omitempty"`
	OS       string          `json:"os,omitempty"`
	Arch     string          `json:"arch,omitempty"`
	Token    string          `json:"token,omitempty"`
	ID       string          `json:"id,omitempty"`
	Op       string          `json:"op,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	OK       bool            `json:"ok,omitempty"`
	Error    string          `json:"error,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

type peer struct {
	conn net.Conn
	mu   sync.Mutex
}

func (p *peer) send(msg message) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(payload) > maxFrameSize {
		return fmt.Errorf("message is too large: %d bytes", len(payload))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	if _, err = p.conn.Write(size[:]); err != nil {
		return err
	}
	_, err = p.conn.Write(payload)
	return err
}

func receive(conn net.Conn) (message, error) {
	var size [4]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return message{}, err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxFrameSize {
		return message{}, fmt.Errorf("invalid frame size: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return message{}, err
	}
	var msg message
	if err := json.Unmarshal(payload, &msg); err != nil {
		return message{}, err
	}
	return msg, nil
}

func tokenEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type registry struct {
	mu      sync.Mutex
	agents  map[string]*peer
	pending map[string]*peer
	waiters map[string]chan message
	devices map[string]*deviceRecord
}

type deviceRecord struct {
	Name      string    `json:"name"`
	Token     string    `json:"token,omitempty"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"last_seen"`
	Connected time.Time `json:"connected_at,omitempty"`
	peer      *peer
}

func newRegistry() *registry {
	return &registry{agents: map[string]*peer{}, pending: map[string]*peer{}, waiters: map[string]chan message{}, devices: map[string]*deviceRecord{}}
}

func (r *registry) setAgent(msg message, p *peer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.agents[msg.Name]; old != nil {
		_ = old.conn.Close()
	}
	now := time.Now()
	r.agents[msg.Name] = p
	r.devices[msg.Name] = &deviceRecord{Name: msg.Name, Token: msg.Token, Hostname: msg.Hostname, OS: msg.OS, Arch: msg.Arch, Online: true, LastSeen: now, Connected: now, peer: p}
	return nil
}

func (r *registry) removeAgent(name string, p *peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.agents[name] == p {
		delete(r.agents, name)
		if device := r.devices[name]; device != nil && device.peer == p {
			device.Online = false
			device.LastSeen = time.Now()
			device.peer = nil
		}
	}
}

func (r *registry) agent(name string) *peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.agents[name]
}

func (r *registry) listDevices() []deviceRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	devices := make([]deviceRecord, 0, len(r.devices))
	for _, device := range r.devices {
		copy := *device
		copy.peer = nil
		devices = append(devices, copy)
	}
	return devices
}

func (r *registry) addPending(id string, p *peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending[id] = p
}

func (r *registry) takePending(id string) *peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.pending[id]
	delete(r.pending, id)
	return p
}

func (r *registry) addWaiter(id string) chan message {
	r.mu.Lock()
	defer r.mu.Unlock()
	channel := make(chan message, 1)
	r.waiters[id] = channel
	return channel
}

func (r *registry) takeWaiter(id string) chan message {
	r.mu.Lock()
	defer r.mu.Unlock()
	channel := r.waiters[id]
	delete(r.waiters, id)
	return channel
}

type relayConfig struct {
	listen     string
	token      string
	cert       string
	key        string
	webListen  string
	webRoot    string
	adminUser  string
	adminPass  string
	adminAPI   string
	adminState string
}

type adminState struct {
	Username     string            `json:"username"`
	PasswordHash string            `json:"password_hash"`
	Notes        map[string]string `json:"notes"`
	DeviceTokens map[string]string `json:"device_tokens"`
}

type adminStore struct {
	mu       sync.Mutex
	path     string
	state    adminState
	apiToken string
	sessions map[string]time.Time
}

func newAdminStore(username, password, apiToken, path string) (*adminStore, error) {
	if username == "" || password == "" || apiToken == "" {
		return nil, nil
	}
	store := &adminStore{path: path, apiToken: apiToken, sessions: map[string]time.Time{}}
	if store.path == "" {
		store.path = "computer-pipe-admin.json"
	}
	store.state = adminState{Username: username, Notes: map[string]string{}, DeviceTokens: map[string]string{}}
	if data, err := os.ReadFile(store.path); err == nil {
		if err := json.Unmarshal(data, &store.state); err != nil {
			return nil, err
		}
		if store.state.Username == "" {
			store.state.Username = username
		}
		if store.state.Notes == nil {
			store.state.Notes = map[string]string{}
		}
		if store.state.DeviceTokens == nil {
			store.state.DeviceTokens = map[string]string{}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if store.state.PasswordHash == "" {
		store.state.PasswordHash = hashPassword(password)
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func randomHex(bytesCount int) string {
	data := make([]byte, bytesCount)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}

func hashPassword(password string) string {
	salt := []byte(randomHex(16))
	digest := sha256.Sum256(append(salt, []byte(password)...))
	value := digest[:]
	for i := 0; i < 120000; i++ {
		next := sha256.Sum256(append(value, []byte(password)...))
		value = next[:]
	}
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(value)
}

func verifyPassword(password, encoded string) bool {
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err1 := hex.DecodeString(parts[0])
	expected, err2 := hex.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	digest := sha256.Sum256(append(salt, []byte(password)...))
	value := digest[:]
	for i := 0; i < 120000; i++ {
		next := sha256.Sum256(append(value, []byte(password)...))
		value = next[:]
	}
	return subtle.ConstantTimeCompare(value, expected) == 1
}

func (s *adminStore) saveLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	temporary := s.path + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, s.path)
}

func (s *adminStore) login(username, password string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if username != s.state.Username || !verifyPassword(password, s.state.PasswordHash) {
		return "", false
	}
	token := randomHex(32)
	s.sessions[token] = time.Now().Add(24 * time.Hour)
	return token, true
}

func (s *adminStore) validSession(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.sessions[token]
	if !ok || time.Now().After(expires) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *adminStore) changePassword(current, next string) error {
	if next == "" {
		return errors.New("new password is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !verifyPassword(current, s.state.PasswordHash) {
		return errors.New("current password is invalid")
	}
	s.state.PasswordHash = hashPassword(next)
	return s.saveLocked()
}

func (s *adminStore) setNote(name, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Notes[name] = note
	return s.saveLocked()
}

func (s *adminStore) notes() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := map[string]string{}
	for name, note := range s.state.Notes {
		result[name] = note
	}
	return result
}

func (s *adminStore) issueDeviceToken(name string) (string, error) {
	if name == "" {
		return "", errors.New("device name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token := randomHex(24)
	s.state.DeviceTokens[name] = token
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *adminStore) validDeviceToken(name, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	registered := s.state.DeviceTokens[name]
	return registered != "" && tokenEqual(registered, token)
}

func (s *adminStore) apiAuthorized(r *http.Request) bool {
	supplied := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(supplied), "bearer ") {
		supplied = supplied[7:]
	} else {
		supplied = r.Header.Get("X-Admin-Token")
	}
	return tokenEqual(supplied, s.apiToken)
}

func listenRelay(cfg relayConfig) (net.Listener, error) {
	if cfg.cert == "" && cfg.key == "" {
		return net.Listen("tcp", cfg.listen)
	}
	if cfg.cert == "" || cfg.key == "" {
		return nil, errors.New("--cert and --key must be provided together")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.cert, cfg.key)
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", cfg.listen, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
}

func runRelay(cfg relayConfig) error {
	ln, err := listenRelay(cfg)
	if err != nil {
		return err
	}
	defer ln.Close()
	registry := newRegistry()
	admin, err := newAdminStore(cfg.adminUser, cfg.adminPass, cfg.adminAPI, cfg.adminState)
	if err != nil {
		return err
	}
	protocol := "tcp"
	if cfg.cert != "" {
		protocol = "tls"
	}
	fmt.Printf("computer-pipe relay listening on %s %s\n", protocol, cfg.listen)
	if cfg.webListen != "" {
		go func() {
			if err := runWebServer(cfg.webListen, cfg.webRoot, cfg.cert, cfg.key, cfg.token, registry, admin); err != nil {
				fmt.Fprintf(os.Stderr, "web server stopped: %v\n", err)
			}
		}()
	}
	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return acceptErr
		}
		configureKeepAlive(conn)
		go serveRelayPeer(conn, registry, cfg.token, admin)
	}
}

func runWebServer(listen, root, cert, key, relayToken string, registry *registry, admin *adminStore) error {
	if (cert == "") != (key == "") {
		return errors.New("web TLS requires both relay --cert and --key")
	}
	if root == "" {
		root = "."
	}
	if _, err := os.Stat(root); err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Pipe-Token")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if admin != nil && (r.URL.Path == "/" || r.URL.Path == "/manage" || strings.HasPrefix(r.URL.Path, "/manage/")) {
			handleAdminHTTP(w, r, admin, registry, relayToken)
			return
		}
		if admin != nil && r.URL.Path == "/deploy" {
			if !adminSessionValid(r, admin) {
				http.Error(w, "login required", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, renderDeployPage(relayToken))
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, renderDeployPage(relayToken))
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" || filepath.Base(name) != name || strings.Contains(name, "..") {
			http.NotFound(w, r)
			return
		}
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, path)
	})
	server := &http.Server{Handler: handler}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if cert != "" {
		fmt.Printf("computer-pipe deployment page: https://%s\n", listen)
		return server.ServeTLS(ln, cert, key)
	}
	fmt.Printf("computer-pipe deployment page: http://%s\n", listen)
	return server.Serve(ln)
}

func adminSessionValid(r *http.Request, admin *adminStore) bool {
	cookie, err := r.Cookie("cpipe_session")
	return err == nil && admin.validSession(cookie.Value)
}

func adminAuthorized(r *http.Request, admin *adminStore) bool {
	return adminSessionValid(r, admin) || admin.apiAuthorized(r)
}

func requestAgent(registry *registry, name, op string, args json.RawMessage) (message, error) {
	device := registry.agent(name)
	if device == nil {
		return message{}, errors.New("device is offline: " + name)
	}
	id := randomHex(16)
	waiter := registry.addWaiter(id)
	if err := device.send(message{Type: "request", ID: id, Op: op, Args: args}); err != nil {
		registry.takeWaiter(id)
		return message{}, err
	}
	select {
	case response := <-waiter:
		if response.Error != "" {
			return response, errors.New(response.Error)
		}
		return response, nil
	case <-time.After(120 * time.Second):
		registry.takeWaiter(id)
		return message{}, errors.New("device request timed out")
	}
}

func writeSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "cpipe_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "cpipe_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func handleAdminHTTP(w http.ResponseWriter, r *http.Request, admin *adminStore, registry *registry, relayToken string) {
	if r.URL.Path == "/" || r.URL.Path == "/manage" || r.URL.Path == "/manage/" {
		if !adminSessionValid(r, admin) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, renderAdminLoginPage())
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, renderAdminDashboardPage())
		return
	}
	if r.URL.Path == "/manage/api/login" && r.Method == http.MethodPost {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeHTTPJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		session, ok := admin.login(body.Username, body.Password)
		if !ok {
			writeHTTPJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
			return
		}
		writeSessionCookie(w, session)
		writeHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if r.URL.Path == "/manage/api/logout" && r.Method == http.MethodPost {
		clearSessionCookie(w)
		writeHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if !adminAuthorized(r, admin) {
		writeHTTPJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	switch {
	case r.URL.Path == "/manage/api/config" && r.Method == http.MethodGet:
		writeHTTPJSON(w, http.StatusOK, map[string]string{"api_token": admin.apiToken, "deploy_path": "/deploy", "base_url": ""})
	case r.URL.Path == "/manage/api/help" && r.Method == http.MethodGet:
		writeHTTPJSON(w, http.StatusOK, map[string]any{
			"authentication": "Authorization: Bearer SERVER_API_TOKEN",
			"endpoints": []map[string]string{
				{"method": "GET", "path": "/manage/api/config", "description": "读取服务器 API Token 和部署入口"},
				{"method": "GET", "path": "/manage/api/devices", "description": "查看设备、在线状态、系统信息、备注、设备 Token 和调用地址"},
				{"method": "GET", "path": "/manage/api/devices/{name}/health", "description": "读取设备健康状态"},
				{"method": "POST", "path": "/manage/api/devices/{name}/command", "description": "在设备上执行命令"},
				{"method": "GET", "path": "/manage/api/devices/{name}/snapshot", "description": "获取设备截图"},
				{"method": "GET/POST", "path": "/manage/api/devices/{name}/clipboard", "description": "读取或写入剪切板"},
				{"method": "POST", "path": "/manage/api/devices/{name}/input", "description": "发送键鼠输入"},
				{"method": "POST", "path": "/manage/api/devices/{name}/note", "description": "修改设备备注"},
				{"method": "POST", "path": "/manage/api/devices/{name}/uninstall", "description": "卸载并下线设备"},
				{"method": "POST", "path": "/manage/api/device-token", "description": "生成设备级 Token，JSON 参数为 name"},
			},
		})
	case r.URL.Path == "/manage/api/device-token" && r.Method == http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeHTTPJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		token, err := admin.issueDeviceToken(body.Name)
		if err != nil {
			writeHTTPError(w, err)
			return
		}
		writeHTTPJSON(w, http.StatusOK, map[string]string{"name": body.Name, "token": token})
	case r.URL.Path == "/manage/api/devices" && r.Method == http.MethodGet:
		devices := registry.listDevices()
		notes := admin.notes()
		result := make([]map[string]any, 0, len(devices))
		for _, device := range devices {
			result = append(result, map[string]any{"name": device.Name, "token": device.Token, "hostname": device.Hostname, "os": device.OS, "arch": device.Arch, "online": device.Online, "last_seen": device.LastSeen, "connected_at": device.Connected, "note": notes[device.Name], "api_base": "/manage/api/devices/" + url.PathEscape(device.Name)})
		}
		writeHTTPJSON(w, http.StatusOK, map[string]any{"devices": result})
	case r.URL.Path == "/manage/api/change-password" && r.Method == http.MethodPost:
		var body struct {
			Current string `json:"current_password"`
			Next    string `json:"new_password"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeHTTPJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := admin.changePassword(body.Current, body.Next); err != nil {
			writeHTTPJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		prefix := "/manage/api/devices/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
			if len(parts) == 2 && parts[0] != "" {
				name := parts[0]
				switch parts[1] {
				case "health", "command", "snapshot", "clipboard", "input":
					handleDeviceProxyHTTP(w, r, registry, name, parts[1])
					return
				case "note":
					if r.Method != http.MethodPost {
						writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
						return
					}
					var body struct {
						Note string `json:"note"`
					}
					if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
						writeHTTPJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
						return
					}
					if err := admin.setNote(name, body.Note); err != nil {
						writeHTTPError(w, err)
						return
					}
					writeHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
					return
				case "uninstall":
					if r.Method != http.MethodPost {
						writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
						return
					}
					device := registry.agent(name)
					if device == nil {
						writeHTTPJSON(w, http.StatusConflict, map[string]string{"error": "device is offline"})
						return
					}
					if err := device.send(message{Type: "request", ID: randomHex(16), Op: "uninstall", Args: json.RawMessage(`{}`)}); err != nil {
						writeHTTPError(w, err)
						return
					}
					writeHTTPJSON(w, http.StatusAccepted, map[string]any{"ok": true, "name": name})
					return
				}
			}
		}
		writeHTTPJSON(w, http.StatusNotFound, map[string]string{"error": "unknown management endpoint"})
	}
	_ = relayToken
}

func handleDeviceProxyHTTP(w http.ResponseWriter, r *http.Request, registry *registry, name, action string) {
	var op string
	var args json.RawMessage
	switch action {
	case "health":
		if r.Method != http.MethodGet {
			writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		op, args = "health", json.RawMessage(`{}`)
	case "snapshot":
		if r.Method != http.MethodGet {
			writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		monitor, _ := strconv.Atoi(r.URL.Query().Get("monitor"))
		args, _ = json.Marshal(snapshotArgs{Monitor: monitor})
		op = "snapshot"
	case "command":
		if r.Method != http.MethodPost {
			writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		op, args = "command", readProxyBody(w, r)
	case "clipboard":
		if r.Method == http.MethodGet {
			op, args = "clipboard-get", json.RawMessage(`{}`)
		} else if r.Method == http.MethodPost {
			op, args = "clipboard-set", readProxyBody(w, r)
		} else {
			writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
			return
		}
	case "input":
		if r.Method != http.MethodPost {
			writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		op, args = "input", readProxyBody(w, r)
	default:
		writeHTTPJSON(w, http.StatusNotFound, map[string]string{"error": "unknown device operation"})
		return
	}
	if args == nil {
		return
	}
	response, err := requestAgent(registry, name, op, args)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	if action == "snapshot" {
		var snapshot struct {
			Mime   string `json:"mime"`
			Base64 string `json:"base64"`
		}
		if err := json.Unmarshal(response.Data, &snapshot); err != nil {
			writeHTTPError(w, err)
			return
		}
		image, err := base64.StdEncoding.DecodeString(snapshot.Base64)
		if err != nil {
			writeHTTPError(w, err)
			return
		}
		mime := snapshot.Mime
		if mime == "" {
			mime = "image/png"
		}
		writeHTTPRawStatus(w, http.StatusOK, mime, image)
		return
	}
	writeHTTPRaw(w, http.StatusOK, response.Data)
}

func readProxyBody(w http.ResponseWriter, r *http.Request) json.RawMessage {
	data, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		writeHTTPError(w, err)
		return nil
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		writeHTTPJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		writeHTTPError(w, err)
		return nil
	}
	return encoded
}

func renderAdminLoginPage() string {
	return strings.Replace(adminLoginPage, "</style>", adminLoginStylePatch+"</style>", 1)
}

func renderAdminDashboardPage() string {
	return adminDashboardPageV2
}

const adminLoginStylePatch = `body{background:radial-gradient(circle at 15% 10%,#284a86 0,#172847 38%,#0d172a 100%);min-height:100vh}main{max-width:460px;margin:0 auto;padding:10vh 20px}.card{border:0;border-radius:20px;padding:34px;box-shadow:0 24px 70px #050b1770}.card h1{font-size:27px;letter-spacing:-.04em}.card h1:before{content:"CP";display:inline-grid;place-items:center;width:30px;height:30px;margin-right:10px;border-radius:10px;background:linear-gradient(135deg,#64a8ff,#316ff6);color:#fff;font-size:11px;vertical-align:3px}.field input{border-color:#dbe2ef;border-radius:10px;padding:12px}.card button{border-radius:10px;background:#316ff6;padding:12px}.error{min-height:18px}`

const adminLoginPage = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>computer-pipe 登录</title><style>body{margin:0;background:#f5f7fb;color:#172033;font:15px system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:420px;margin:90px auto;padding:0 20px}.card{background:#fff;border:1px solid #e5e9f2;border-radius:14px;padding:24px;box-shadow:0 4px 16px #1720330b}h1{margin:0 0 18px;font-size:25px}.field{display:flex;flex-direction:column;gap:6px;margin:12px 0}.field label{font-size:13px;color:#5b667c}.field input{border:1px solid #d7ddea;border-radius:8px;padding:10px;font:inherit}button{width:100%;background:#2f6fed;color:#fff;border:0;border-radius:8px;padding:11px;font:inherit;cursor:pointer}.error{color:#bd2b2b;margin-top:12px}</style></head><body><main><div class="card"><h1>computer-pipe</h1><div class="field"><label>账号</label><input id="username" autocomplete="username"></div><div class="field"><label>密码</label><input id="password" type="password" autocomplete="current-password"></div><button id="login">登录</button><div id="error" class="error"></div></div></main><script>document.getElementById('login').onclick=async()=>{const body={username:document.getElementById('username').value,password:document.getElementById('password').value};const response=await fetch('/manage/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(response.ok){location.href='/manage'}else{document.getElementById('error').textContent=(await response.json()).error||'登录失败'}};</script></body></html>`

func renderDeployPage(relayToken string) string {
	return strings.ReplaceAll(deployPage, "__PIPE_TOKEN__", relayToken)
}

const deployPage = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>computer-pipe 一键部署</title>
<style>
body{margin:0;background:#f5f7fb;color:#172033;font:15px system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:900px;margin:36px auto;padding:0 20px}h1{font-size:28px;margin:0 0 8px}.sub{color:#68738a;margin-bottom:26px}.card{background:#fff;border:1px solid #e5e9f2;border-radius:14px;padding:20px;margin:14px 0;box-shadow:0 4px 16px #1720330b}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.field{display:flex;flex-direction:column;gap:6px}.field label{font-size:13px;color:#5b667c}.field input,.field select{border:1px solid #d7ddea;border-radius:8px;padding:10px;font:inherit}.wide{grid-column:1/-1}button{background:#2f6fed;color:#fff;border:0;border-radius:8px;padding:11px 16px;font:inherit;cursor:pointer}pre{white-space:pre-wrap;word-break:break-word;background:#101827;color:#d6e1f5;padding:14px;border-radius:10px;line-height:1.5}.hint{color:#68738a;font-size:13px}code{background:#eef2f8;border-radius:4px;padding:2px 5px}@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style></head><body><main>
<h1>computer-pipe 一键部署</h1><div class="sub">选择连接方式，生成 Windows、Linux、macOS 安装命令。</div>
<div class="card"><div class="grid">
<div class="field"><label>连接方式</label><select id="mode"><option value="relay">外网 relay</option><option value="lan">内网直连</option></select></div>
<div class="field"><label>设备名称</label><input id="name" value="B"></div>
<div class="field wide"><label>pipe 凭证</label><input id="token" value="__PIPE_TOKEN__" readonly></div>
</div><p class="hint">外网模式固定连接 129.204.22.176；内网模式固定监听 0.0.0.0:17602。控制端调用局域网 API 时使用上面的凭证。</p><button id="generate">生成命令</button><p id="notice" class="hint"></p></div>
<div class="card"><h3>Linux / macOS</h3><pre id="unix"></pre></div>
<div class="card"><h3>Windows PowerShell</h3><pre id="windows"></pre></div>
<div class="card"><h3>局域网接口</h3><pre>GET  http://目标IP:17602/api/v1/health
POST http://目标IP:17602/api/v1/command
GET  http://目标IP:17602/api/v1/snapshot
GET/POST http://目标IP:17602/api/v1/clipboard
POST http://目标IP:17602/api/v1/input
请求头：Authorization: Bearer PIPE_TOKEN</pre></div>
</main><script>
const $=id=>document.getElementById(id);
function sh(v){return "'"+String(v??"").replaceAll("'","'\\''")+"'"}
function ps(v){return "'"+String(v??"").replaceAll("'","''")+"'"}
function generate(){
  const mode=$("mode").value, base="https://129.204.22.176:17601", name=$("name").value||"B", token=$("token").value;
  $("notice").textContent="";
  const env={PIPE_NAME:name,PIPE_TOKEN:token,PIPE_LISTEN:"0.0.0.0:17602",PIPE_DOWNLOAD_BASE:base,PIPE_INSECURE:"1"};
  if(mode==="lan"){env.PIPE_MODE="direct"}else{env.PIPE_MODE="relay";env.PIPE_RELAY="129.204.22.176:17600";env.PIPE_TLS="1";env.PIPE_INSECURE="1"}
  const unixEnv=Object.entries(env).map(([k,v])=>k+"="+sh(v)).join(" ");
  const curlFlags="-kfsSL";
  $("unix").textContent="curl "+curlFlags+" "+sh(base+"/install.sh")+" | "+unixEnv+" sh";
  const winEnv=Object.entries(env).map(([k,v])=>"$env:"+k+"="+ps(v)).join(";");
  const winFetch="((curl.exe -kfsSL "+ps(base+"/install.ps1")+") -join ([Environment]::NewLine))";
  $("windows").textContent=winEnv+"; iex ("+winFetch+")";
}
async function prepareToken(){const name=$("name").value||"B";const response=await fetch('/manage/api/device-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})});if(!response.ok){$("notice").textContent="设备 Token 生成失败";return}const data=await response.json();$("token").value=data.token;generate()}
$("name").addEventListener('change',prepareToken);$("generate").onclick=generate;prepareToken();
</script></body></html>`

func serveRelayPeer(conn net.Conn, registry *registry, expectedToken string, admin *adminStore) {
	defer conn.Close()
	p := &peer{conn: conn}
	first, err := receive(conn)
	if err != nil {
		fmt.Printf("relay handshake error from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	if first.Type != "hello" || first.Version != protocolVersion {
		_ = p.send(message{Type: "error", Error: "invalid handshake"})
		return
	}
	if first.Role == "agent" {
		if first.Name == "" {
			_ = p.send(message{Type: "error", Error: "agent name is required"})
			return
		}
		if !tokenEqual(first.Token, expectedToken) && (admin == nil || !admin.validDeviceToken(first.Name, first.Token)) {
			_ = p.send(message{Type: "error", Error: "invalid device token"})
			return
		}
		_ = registry.setAgent(first, p)
		if err := p.send(message{Type: "hello_ok", Name: first.Name}); err != nil {
			return
		}
		fmt.Printf("agent connected: %s from %s\n", first.Name, conn.RemoteAddr())
		for {
			msg, readErr := receive(conn)
			if readErr != nil {
				registry.removeAgent(first.Name, p)
				fmt.Printf("agent disconnected: %s (%v)\n", first.Name, readErr)
				return
			}
			if msg.Type == "response" {
				if waiter := registry.takeWaiter(msg.ID); waiter != nil {
					waiter <- msg
					continue
				}
				client := registry.takePending(msg.ID)
				if client != nil {
					_ = client.send(msg)
				}
			}
		}
	}
	if first.Role != "client" || first.Name == "" {
		_ = p.send(message{Type: "error", Error: "client target name is required"})
		return
	}
	if !tokenEqual(first.Token, expectedToken) && (admin == nil || !admin.validDeviceToken(first.Name, first.Token)) {
		_ = p.send(message{Type: "error", Error: "invalid device token"})
		return
	}
	agent := registry.agent(first.Name)
	if agent == nil {
		_ = p.send(message{Type: "error", Error: "agent is offline: " + first.Name})
		return
	}
	if err := p.send(message{Type: "hello_ok", Name: first.Name}); err != nil {
		return
	}
	for {
		msg, readErr := receive(conn)
		if readErr != nil {
			return
		}
		if msg.Type != "request" || msg.ID == "" || msg.Op == "" {
			_ = p.send(message{Type: "error", Error: "invalid request"})
			continue
		}
		registry.addPending(msg.ID, p)
		if err := agent.send(msg); err != nil {
			registry.takePending(msg.ID)
			_ = p.send(message{Type: "response", ID: msg.ID, Error: err.Error()})
		}
	}
}

type endpoint struct {
	address  string
	tls      bool
	insecure bool
}

func dialEndpoint(ep endpoint) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 5 * time.Second}
	if !ep.tls {
		conn, err := dialer.Dial("tcp", ep.address)
		if err != nil {
			return nil, err
		}
		configureKeepAlive(conn)
		return conn, nil
	}
	return tls.DialWithDialer(dialer, "tcp", ep.address, &tls.Config{InsecureSkipVerify: ep.insecure, MinVersion: tls.VersionTLS12})
}

func configureKeepAlive(conn net.Conn) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(5 * time.Second)
}

func connectHello(ep endpoint, role, name, token string) (*peer, error) {
	conn, err := dialEndpoint(ep)
	if err != nil {
		return nil, err
	}
	p := &peer{conn: conn}
	hello := message{Type: "hello", Version: protocolVersion, Role: role, Name: name, Token: token}
	if role == "agent" {
		hello.Hostname = hostname()
		hello.OS = runtime.GOOS
		hello.Arch = runtime.GOARCH
	}
	if err := p.send(hello); err != nil {
		_ = conn.Close()
		return nil, err
	}
	response, err := receive(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if response.Type == "error" {
		_ = conn.Close()
		return nil, errors.New(response.Error)
	}
	if response.Type != "hello_ok" {
		_ = conn.Close()
		return nil, errors.New("relay returned an invalid handshake response")
	}
	return p, nil
}

func runAgent(ep endpoint, name, token, httpListen, httpToken string) error {
	if name == "" || token == "" {
		return errors.New("agent requires --name and --token")
	}
	if httpListen != "" {
		if httpToken == "" {
			httpToken = token
		}
		go func() {
			if err := runLocalHTTP(httpListen, httpToken); err != nil {
				fmt.Fprintf(os.Stderr, "local HTTP API stopped: %v\n", err)
			}
		}()
	}
	for {
		p, err := connectHello(ep, "agent", name, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent connect failed: %v; retrying in 3s\n", err)
			time.Sleep(3 * time.Second)
			continue
		}
		fmt.Printf("agent connected to %s as %s\n", ep.address, name)
		err = serveAgent(p)
		_ = p.conn.Close()
		fmt.Fprintf(os.Stderr, "agent connection closed: %v; retrying in 3s\n", err)
	}
}

func serveAgent(p *peer) error {
	for {
		msg, err := receive(p.conn)
		if err != nil {
			return err
		}
		if msg.Type != "request" {
			continue
		}
		data, opErr := executeOperation(msg.Op, msg.Args)
		response := message{Type: "response", ID: msg.ID, OK: opErr == nil}
		if opErr != nil {
			response.Error = opErr.Error()
		} else {
			response.Data = data
		}
		if err := p.send(response); err != nil {
			return err
		}
		if msg.Op == "uninstall" && opErr == nil {
			go func() {
				time.Sleep(800 * time.Millisecond)
				os.Exit(0)
			}()
		}
	}
}

func runClient(ep endpoint, token, target, op string, args any) error {
	p, err := connectHello(ep, "client", target, token)
	if err != nil {
		return err
	}
	defer p.conn.Close()
	encoded, err := json.Marshal(args)
	if err != nil {
		return err
	}
	id := strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := p.send(message{Type: "request", ID: id, Op: op, Args: encoded}); err != nil {
		return err
	}
	response, err := receive(p.conn)
	if err != nil {
		return err
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	return printOperationResult(op, response.Data)
}

func executeOperation(op string, raw json.RawMessage) (json.RawMessage, error) {
	switch op {
	case "health":
		return json.Marshal(map[string]any{"ok": true, "hostname": hostname(), "os": runtime.GOOS, "arch": runtime.GOARCH})
	case "command":
		var args commandArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		return runRemoteCommand(args)
	case "snapshot":
		var args snapshotArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		png, err := captureScreen()
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"mime": "image/png", "base64": base64.StdEncoding.EncodeToString(png), "monitor": args.Monitor})
	case "clipboard-get":
		text, err := clipboardGet()
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"text": text})
	case "clipboard-set":
		var args textArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if err := clipboardSet(args.Text); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true, "length": len([]rune(args.Text))})
	case "input":
		var args inputArgs
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if err := performInput(args); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true, "action": args.Action})
	case "uninstall":
		return uninstallSelf()
	default:
		return nil, fmt.Errorf("unsupported operation: %s", op)
	}
}

func uninstallSelf() (json.RawMessage, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "windows" {
		command := fmt.Sprintf("ping 127.0.0.1 -n 3 > nul & del /f /q \"%s\"", executable)
		if err := exec.Command("cmd.exe", "/d", "/s", "/c", command).Start(); err != nil {
			return nil, err
		}
	} else {
		quoted := strings.ReplaceAll(executable, "'", "'\\''")
		if err := exec.Command("sh", "-c", "sleep 1; rm -f -- '"+quoted+"'").Start(); err != nil {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{"ok": true, "scheduled": true, "path": executable})
}

type localAPIHandler struct {
	token string
}

func (h localAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Pipe-Token")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/docs" || r.URL.Path == "/index.html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, localAPIPage)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/docs.md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = io.WriteString(w, localAPIMarkdown)
		return
	}
	if !httpAuthorized(r, h.token) {
		writeHTTPJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
		return
	}
	switch r.URL.Path {
	case "/api/v1/help":
		writeHTTPJSON(w, http.StatusOK, map[string]any{
			"name":          "computer-pipe local API",
			"authorization": "Authorization: Bearer PIPE_TOKEN",
			"endpoints": []map[string]string{
				{"method": "GET", "path": "/api/v1/health", "example": "curl -H 'Authorization: Bearer PIPE_TOKEN' http://TARGET:17602/api/v1/health"},
				{"method": "POST", "path": "/api/v1/command", "body": `{"command":"git status","cwd":"/workspace","timeout":120}`},
				{"method": "GET", "path": "/api/v1/snapshot", "result": "image/png"},
				{"method": "GET/POST", "path": "/api/v1/clipboard", "body": `{"text":"hello"}`},
				{"method": "POST", "path": "/api/v1/input", "body": `{"action":"key","key":"c","modifiers":["ctrl"]}`},
			},
		})
	case "/api/v1/health":
		handleLocalOperation(w, "health", json.RawMessage(`{}`))
	case "/api/v1/command":
		if r.Method != http.MethodPost {
			writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST required"})
			return
		}
		handleLocalJSONOperation(w, r, "command")
	case "/api/v1/snapshot":
		if r.Method != http.MethodGet {
			writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "GET required"})
			return
		}
		monitor, _ := strconv.Atoi(r.URL.Query().Get("monitor"))
		data, err := captureScreen()
		if err != nil {
			writeHTTPError(w, err)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=computer-pipe-monitor-%d.png", monitor))
		_, _ = w.Write(data)
	case "/api/v1/clipboard":
		if r.Method == http.MethodGet {
			handleLocalOperation(w, "clipboard-get", json.RawMessage(`{}`))
			return
		}
		if r.Method == http.MethodPost {
			handleLocalJSONOperation(w, r, "clipboard-set")
			return
		}
		writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "GET or POST required"})
	case "/api/v1/input":
		if r.Method != http.MethodPost {
			writeHTTPJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST required"})
			return
		}
		handleLocalJSONOperation(w, r, "input")
	default:
		writeHTTPJSON(w, http.StatusNotFound, map[string]any{"error": "unknown path"})
	}
}

const localAPIPage = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>computer-pipe 局域网 API</title>
<style>
body{margin:0;background:#f5f7fb;color:#172033;font:15px system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:980px;margin:32px auto;padding:0 20px}h1{margin:0 0 8px;font-size:28px}.sub{color:#68738a;margin-bottom:24px}.card{background:#fff;border:1px solid #e5e9f2;border-radius:14px;padding:18px 20px;margin:14px 0;box-shadow:0 4px 16px #1720330b}h2{font-size:19px;margin:0 0 10px}h3{font-size:16px;margin:18px 0 8px}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #edf0f5;padding:9px 6px;vertical-align:top}th{color:#5b667c;font-weight:500}code{background:#eef2f8;border-radius:4px;padding:2px 5px}pre{white-space:pre-wrap;word-break:break-word;background:#101827;color:#d6e1f5;padding:13px;border-radius:10px;line-height:1.5;margin:8px 0}.muted{color:#68738a;font-size:13px}@media(max-width:700px){main{margin:20px auto;padding:0 12px}table{font-size:13px}}
</style></head><body><main>
<h1>computer-pipe 局域网 API</h1>
<div class="sub">控制端无需安装客户端，使用 HTTP 请求即可调用目标电脑。</div>
<div class="card"><h2>请求方式</h2><p>目标地址示例 <code>http://192.168.1.20:17602</code></p><p>接口统一使用一个请求头。</p><pre>Authorization: Bearer PIPE_TOKEN</pre><p class="muted">根页面不需要凭证，接口请求需要凭证。错误会返回 JSON。</p></div>
<div class="card"><h2>接口列表</h2><table><tr><th>方法</th><th>路径</th><th>作用</th></tr>
<tr><td>GET</td><td><code>/api/v1/health</code></td><td>查看目标主机、系统和架构</td></tr>
<tr><td>POST</td><td><code>/api/v1/command</code></td><td>执行命令</td></tr>
<tr><td>GET</td><td><code>/api/v1/snapshot?monitor=0</code></td><td>返回主屏 PNG 图片</td></tr>
<tr><td>GET</td><td><code>/api/v1/clipboard</code></td><td>读取文本剪切板</td></tr>
<tr><td>POST</td><td><code>/api/v1/clipboard</code></td><td>写入文本剪切板</td></tr>
<tr><td>POST</td><td><code>/api/v1/input</code></td><td>发送键盘和鼠标输入</td></tr>
<tr><td>GET</td><td><code>/api/v1/help</code></td><td>返回机器可读的接口说明</td></tr></table></div>
<div class="card"><h2>健康检查</h2><pre>curl -H "Authorization: Bearer PIPE_TOKEN" \
  http://192.168.1.20:17602/api/v1/health</pre><pre>Invoke-RestMethod -Uri http://192.168.1.20:17602/api/v1/health -Headers @{Authorization="Bearer PIPE_TOKEN"}</pre></div>
<div class="card"><h2>执行命令</h2><p>字段 <code>command</code> 必填，<code>cwd</code> 和 <code>timeout</code> 可选。</p><pre>curl -X POST \
  -H "Authorization: Bearer PIPE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"git status","cwd":"D:/project","timeout":120}' \
  http://192.168.1.20:17602/api/v1/command</pre><pre>$body = @{command="git status"; cwd="D:\project"; timeout=120} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://192.168.1.20:17602/api/v1/command -Headers @{Authorization="Bearer PIPE_TOKEN"} -ContentType "application/json" -Body $body</pre><p class="muted">返回 command、cwd、exit_code、stdout、stderr 和 duration_ms。</p></div>
<div class="card"><h2>截图</h2><pre>curl -o screen.png \
  -H "Authorization: Bearer PIPE_TOKEN" \
  "http://192.168.1.20:17602/api/v1/snapshot?monitor=0"</pre><p class="muted">当前返回主显示器 PNG。</p></div>
<div class="card"><h2>剪切板</h2><pre>curl -H "Authorization: Bearer PIPE_TOKEN" \
  http://192.168.1.20:17602/api/v1/clipboard

curl -X POST \
  -H "Authorization: Bearer PIPE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"text":"hello"}' \
  http://192.168.1.20:17602/api/v1/clipboard</pre></div>
<div class="card"><h2>键盘和鼠标</h2><p><code>action</code> 支持 <code>move</code>、<code>click</code>、<code>scroll</code>、<code>key</code>、<code>text</code>。</p><pre>{"action":"move","x":500,"y":300}
{"action":"click","button":"left","x":500,"y":300}
{"action":"scroll","amount":-720}
{"action":"key","key":"c","modifiers":["ctrl"]}
{"action":"text","text":"hello"}</pre><pre>curl -X POST \
  -H "Authorization: Bearer PIPE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"key","key":"c","modifiers":["ctrl"]}' \
  http://192.168.1.20:17602/api/v1/input</pre></div>
<div class="card"><h2>机器可读帮助</h2><pre>curl -H "Authorization: Bearer PIPE_TOKEN" \
  http://192.168.1.20:17602/api/v1/help</pre></div>
</main></body></html>`

func httpAuthorized(r *http.Request, expected string) bool {
	supplied := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(supplied), "bearer ") {
		supplied = supplied[7:]
	} else {
		supplied = r.Header.Get("X-Pipe-Token")
	}
	return expected != "" && tokenEqual(supplied, expected)
}

func handleLocalJSONOperation(w http.ResponseWriter, r *http.Request, op string) {
	var body map[string]any
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	if err := decoder.Decode(&body); err != nil {
		writeHTTPJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	raw, err := json.Marshal(body)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	handleLocalOperation(w, op, raw)
}

func handleLocalOperation(w http.ResponseWriter, op string, raw json.RawMessage) {
	data, err := executeOperation(op, raw)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	writeHTTPRaw(w, http.StatusOK, data)
}

func writeHTTPError(w http.ResponseWriter, err error) {
	writeHTTPJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "type": fmt.Sprintf("%T", err)})
}

func writeHTTPJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeHTTPRawStatus(w, status, "application/json; charset=utf-8", data)
}

func writeHTTPRaw(w http.ResponseWriter, status int, data []byte) {
	writeHTTPRawStatus(w, status, "application/json; charset=utf-8", data)
}

func writeHTTPRawStatus(w http.ResponseWriter, status int, contentType string, data []byte) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func runLocalHTTP(listen, token string) error {
	if token == "" {
		return errors.New("local HTTP API requires a token")
	}
	server := &http.Server{Addr: listen, Handler: localAPIHandler{token: token}}
	fmt.Printf("computer-pipe local API listening on http://%s\n", listen)
	return server.ListenAndServe()
}

type commandArgs struct {
	Command string `json:"command"`
	CWD     string `json:"cwd,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
}

type snapshotArgs struct {
	Monitor int `json:"monitor,omitempty"`
}

type textArgs struct {
	Text string `json:"text"`
}

type inputArgs struct {
	Action    string   `json:"action"`
	X         int      `json:"x,omitempty"`
	Y         int      `json:"y,omitempty"`
	Button    string   `json:"button,omitempty"`
	Amount    int      `json:"amount,omitempty"`
	Key       string   `json:"key,omitempty"`
	Modifiers []string `json:"modifiers,omitempty"`
	Text      string   `json:"text,omitempty"`
}

func runRemoteCommand(args commandArgs) (json.RawMessage, error) {
	if args.Command == "" {
		return nil, errors.New("command is required")
	}
	if args.Timeout <= 0 {
		args.Timeout = 120
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Timeout)*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/d", "/s", "/c", args.Command)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", args.Command)
	}
	if args.CWD != "" {
		cmd.Dir = args.CWD
	}
	workingDir := cmd.Dir
	if workingDir == "" {
		workingDir, _ = os.Getwd()
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	started := time.Now()
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("command timed out after %ds", args.Timeout)
	}
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{
		"command":     args.Command,
		"cwd":         workingDir,
		"exit_code":   exitCode,
		"stdout":      stdout.String(),
		"stderr":      stderr.String(),
		"duration_ms": time.Since(started).Milliseconds(),
	})
}

func hostname() string {
	value, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return value
}

func printOperationResult(op string, data json.RawMessage) error {
	if op == "snapshot" {
		var value struct {
			Base64 string `json:"base64"`
			Mime   string `json:"mime"`
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		return errors.New("snapshot output requires --output")
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

func runSnapshotClient(ep endpoint, token, target string, monitor int, output string) error {
	p, err := connectHello(ep, "client", target, token)
	if err != nil {
		return err
	}
	defer p.conn.Close()
	encoded, _ := json.Marshal(snapshotArgs{Monitor: monitor})
	if err := p.send(message{Type: "request", ID: strconv.FormatInt(time.Now().UnixNano(), 10), Op: "snapshot", Args: encoded}); err != nil {
		return err
	}
	response, err := receive(p.conn)
	if err != nil {
		return err
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	var value struct {
		Base64 string `json:"base64"`
	}
	if err := json.Unmarshal(response.Data, &value); err != nil {
		return err
	}
	png, err := base64.StdEncoding.DecodeString(value.Base64)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, png, 0600); err != nil {
		return err
	}
	fmt.Printf("saved %s (%d bytes)\n", output, len(png))
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "relay":
		err = relayCommand(os.Args[2:])
	case "agent":
		err = agentCommand(os.Args[2:])
	case "client":
		err = clientCommand(os.Args[2:])
	case "frpc-config":
		err = frpcConfigCommand(os.Args[2:])
	case "version":
		fmt.Println("computer-pipe dev")
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("computer-pipe relay|agent|client|frpc-config")
	fmt.Println("  relay  --listen :17600 --web-listen :17601 --web-root ./web --token TOKEN [--cert server.crt --key server.key]")
	fmt.Println("  agent  --direct --token TOKEN [--listen 0.0.0.0:17602]")
	fmt.Println("  agent  --relay host:6000 --name B --token TOKEN [--tls] [--listen 0.0.0.0:17602]")
	fmt.Println("  agent  --frps-addr host:7000 --frps-token FRPS_TOKEN --frps-remote-port 16000 --name B --token TOKEN [--listen 0.0.0.0:17602]")
	fmt.Println("  client --relay host:6000 --target B --token TOKEN <health|command|snapshot|clipboard-get|clipboard-set|input>")
}

func relayCommand(argv []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", ":6000", "listen address")
	token := fs.String("token", "", "shared token")
	cert := fs.String("cert", "", "TLS certificate")
	key := fs.String("key", "", "TLS private key")
	webListen := fs.String("web-listen", ":17601", "deployment page listen address; empty disables it")
	webRoot := fs.String("web-root", ".", "directory containing binaries and installer scripts")
	adminUser := fs.String("admin-user", os.Getenv("PIPE_ADMIN_USER"), "management page username")
	adminPass := fs.String("admin-password", os.Getenv("PIPE_ADMIN_PASSWORD"), "management page password")
	adminAPI := fs.String("admin-api-token", os.Getenv("PIPE_ADMIN_API_TOKEN"), "management API token")
	adminState := fs.String("admin-state", os.Getenv("PIPE_ADMIN_STATE"), "management state file")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *token == "" {
		return errors.New("relay requires --token")
	}
	return runRelay(relayConfig{listen: *listen, token: *token, cert: *cert, key: *key, webListen: *webListen, webRoot: *webRoot, adminUser: *adminUser, adminPass: *adminPass, adminAPI: *adminAPI, adminState: *adminState})
}

func agentCommand(argv []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	direct := fs.Bool("direct", false, "run only the local HTTP API")
	relay := fs.String("relay", "", "relay address")
	frpsAddr := fs.String("frps-addr", "", "existing frps address")
	frpsToken := fs.String("frps-token", "", "existing frps token")
	frpsRemotePort := fs.Int("frps-remote-port", 0, "public frps proxy port")
	frpcPath := fs.String("frpc", "frpc", "frpc executable")
	localRelayPort := fs.Int("local-relay-port", 6000, "local relay port when using frps")
	httpListen := fs.String("listen", "", "local HTTP API listen address, for example 0.0.0.0:17602")
	httpToken := fs.String("listen-token", "", "local HTTP API token, defaults to --token")
	name := fs.String("name", "", "device name")
	token := fs.String("token", "", "shared token")
	tlsEnabled := fs.Bool("tls", false, "use TLS")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *relay != "" && *frpsAddr != "" {
		return errors.New("agent accepts either --relay or --frps-addr")
	}
	if *direct {
		if *relay != "" || *frpsAddr != "" {
			return errors.New("agent --direct cannot be combined with --relay or --frps-addr")
		}
		if *httpListen == "" {
			*httpListen = "0.0.0.0:17602"
		}
		if *token == "" {
			return errors.New("agent --direct requires --token")
		}
		if *httpToken == "" {
			*httpToken = *token
		}
		return runLocalHTTP(*httpListen, *httpToken)
	}
	if *frpsAddr != "" {
		if *frpsRemotePort == 0 {
			return errors.New("--frps-remote-port is required with --frps-addr")
		}
		return runAgentThroughFrps(*frpsAddr, *frpsToken, *frpsRemotePort, *frpcPath, *localRelayPort, *name, *token, *httpListen, *httpToken)
	}
	if *relay == "" {
		return errors.New("agent requires --relay or --frps-addr")
	}
	return runAgent(endpoint{address: *relay, tls: *tlsEnabled, insecure: *insecure}, *name, *token, *httpListen, *httpToken)
}

func runAgentThroughFrps(frpsAddr, frpsToken string, remotePort int, frpcPath string, localPort int, name, pipeToken, httpListen, httpToken string) error {
	if name == "" || pipeToken == "" {
		return errors.New("agent requires --name and --token")
	}
	if frpsToken == "" {
		return errors.New("--frps-token is required with --frps-addr")
	}
	localAddr := "127.0.0.1:" + strconv.Itoa(localPort)
	go func() {
		if err := runRelay(relayConfig{listen: localAddr, token: pipeToken}); err != nil {
			fmt.Fprintf(os.Stderr, "local relay stopped: %v\n", err)
		}
	}()
	serverAddr, serverPort, err := splitServerAddress(frpsAddr)
	if err != nil {
		return err
	}
	config, cleanup, err := writeFrpcTempConfig(serverAddr, serverPort, frpsToken, name, localPort, remotePort)
	if err != nil {
		return err
	}
	defer cleanup()
	frpc := exec.Command(frpcPath, "-c", config)
	frpc.Stdout = os.Stdout
	frpc.Stderr = os.Stderr
	if err := frpc.Start(); err != nil {
		return fmt.Errorf("start frpc: %w", err)
	}
	defer frpc.Process.Kill()
	fmt.Printf("frpc connected through %s; public relay port %d\n", frpsAddr, remotePort)
	return runAgent(endpoint{address: localAddr}, name, pipeToken, httpListen, httpToken)
}

func splitServerAddress(address string) (string, int, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		if strings.Contains(address, ":") {
			return "", 0, fmt.Errorf("invalid frps address %q: %w", address, err)
		}
		return address, 7000, nil
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid frps port: %s", portText)
	}
	return host, port, nil
}

func writeFrpcTempConfig(serverAddr string, serverPort int, token, name string, localPort, remotePort int) (string, func(), error) {
	path, cleanup, err := tempOutputPath(".toml")
	if err != nil {
		return "", nil, err
	}
	content := fmt.Sprintf("serverAddr = %q\nserverPort = %d\nauth.token = %q\n\n[[proxies]]\nname = %q\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nremotePort = %d\n", serverAddr, serverPort, token, name, localPort, remotePort)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func clientCommand(argv []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	relay := fs.String("relay", "", "relay address")
	target := fs.String("target", "", "agent name")
	token := fs.String("token", "", "shared token")
	tlsEnabled := fs.Bool("tls", false, "use TLS")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	output := fs.String("output", "", "snapshot output path")
	monitor := fs.Int("monitor", 0, "monitor index")
	cwd := fs.String("cwd", "", "remote command working directory")
	timeout := fs.Int("timeout", 120, "remote command timeout seconds")
	button := fs.String("button", "left", "mouse button")
	modifiers := fs.String("modifiers", "", "key modifiers separated by comma")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *relay == "" || *target == "" || *token == "" {
		return errors.New("client requires --relay, --target and --token")
	}
	args := fs.Args()
	ep := endpoint{address: *relay, tls: *tlsEnabled, insecure: *insecure}
	if len(args) == 0 {
		return errors.New("client operation is required")
	}
	switch args[0] {
	case "health":
		return runClient(ep, *token, *target, "health", map[string]any{})
	case "command":
		if len(args) < 2 {
			return errors.New("client command requires a command string")
		}
		return runClient(ep, *token, *target, "command", commandArgs{Command: strings.Join(args[1:], " "), CWD: *cwd, Timeout: *timeout})
	case "snapshot":
		if *output == "" {
			return errors.New("client snapshot requires --output")
		}
		return runSnapshotClient(ep, *token, *target, *monitor, *output)
	case "clipboard-get":
		return runClient(ep, *token, *target, "clipboard-get", map[string]any{})
	case "clipboard-set":
		if len(args) < 2 {
			return errors.New("client clipboard-set requires text")
		}
		return runClient(ep, *token, *target, "clipboard-set", textArgs{Text: strings.Join(args[1:], " ")})
	case "input":
		return clientInput(ep, *token, *target, args[1:], *button, *modifiers)
	default:
		return fmt.Errorf("unknown client operation: %s", args[0])
	}
}

func clientInput(ep endpoint, token, target string, args []string, button, modifiers string) error {
	if len(args) == 0 {
		return errors.New("client input action is required")
	}
	value := inputArgs{Action: args[0], Button: button}
	switch value.Action {
	case "move":
		if len(args) != 3 {
			return errors.New("input move requires x y")
		}
		value.X, _ = strconv.Atoi(args[1])
		value.Y, _ = strconv.Atoi(args[2])
	case "click":
		if len(args) == 3 {
			value.X, _ = strconv.Atoi(args[1])
			value.Y, _ = strconv.Atoi(args[2])
		} else if len(args) != 1 {
			return errors.New("input click accepts optional x y")
		}
	case "scroll":
		if len(args) != 2 {
			return errors.New("input scroll requires amount")
		}
		value.Amount, _ = strconv.Atoi(args[1])
	case "key":
		if len(args) != 2 {
			return errors.New("input key requires key")
		}
		value.Key = args[1]
		if modifiers != "" {
			value.Modifiers = strings.Split(modifiers, ",")
		}
	case "text":
		if len(args) < 2 {
			return errors.New("input text requires text")
		}
		value.Text = strings.Join(args[1:], " ")
	default:
		return fmt.Errorf("unknown input action: %s", value.Action)
	}
	return runClient(ep, token, target, "input", value)
}

func frpcConfigCommand(argv []string) error {
	fs := flag.NewFlagSet("frpc-config", flag.ContinueOnError)
	serverAddr := fs.String("server-addr", "", "frps address")
	serverPort := fs.Int("server-port", 7000, "frps port")
	frpToken := fs.String("frp-token", "", "frps token")
	name := fs.String("name", "computer-pipe", "proxy name")
	remotePort := fs.Int("remote-port", 0, "public port")
	localPort := fs.Int("local-port", 6000, "local port")
	output := fs.String("output", "", "output path")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *serverAddr == "" || *remotePort == 0 {
		return errors.New("frpc-config requires --server-addr and --remote-port")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = %q\nserverPort = %d\n\n", *serverAddr, *serverPort)
	if *frpToken != "" {
		fmt.Fprintf(&b, "auth.token = %q\n\n", *frpToken)
	}
	fmt.Fprintf(&b, "[[proxies]]\nname = %q\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nremotePort = %d\n", *name, *localPort, *remotePort)
	if *output == "" {
		fmt.Print(b.String())
		return nil
	}
	return os.WriteFile(*output, []byte(b.String()), 0600)
}

func commandOutput(command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	return cmd.Output()
}

func tempOutputPath(ext string) (string, func(), error) {
	file, err := os.CreateTemp("", "computer-pipe-*-"+ext)
	if err != nil {
		return "", nil, err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		return "", nil, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func captureScreen() ([]byte, error) {
	path, cleanup, err := tempOutputPath(".png")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	switch runtime.GOOS {
	case "windows":
		if err := runPowerShellScreen(path); err != nil {
			return nil, err
		}
	case "darwin":
		if _, err := commandOutput("screencapture", "-x", path); err != nil {
			return nil, err
		}
	default:
		if _, err := exec.LookPath("gnome-screenshot"); err == nil {
			if _, err := commandOutput("gnome-screenshot", "-f", path); err != nil {
				return nil, err
			}
		} else if _, err := exec.LookPath("scrot"); err == nil {
			if _, err := commandOutput("scrot", path); err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("Linux snapshot requires gnome-screenshot or scrot")
		}
	}
	return os.ReadFile(path)
}

func runPowerShell(script string, stdin string) ([]byte, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("powershell: %s", strings.TrimSpace(stderr.String()))
		}
		return nil, err
	}
	return out, nil
}

func runPowerShellScreen(path string) error {
	script := `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Drawing; Add-Type -AssemblyName System.Windows.Forms; $b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $i=New-Object System.Drawing.Bitmap($b.Width,$b.Height); $g=[System.Drawing.Graphics]::FromImage($i); $g.CopyFromScreen($b.Left,$b.Top,0,0,$i.Size); $i.Save($env:PIPE_SCREEN_PATH,[System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $i.Dispose()`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(os.Environ(), "PIPE_SCREEN_PATH="+path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("powershell screen capture: %s", strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}

func clipboardGet() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := runPowerShell("$ErrorActionPreference='Stop'; Get-Clipboard -Raw", "")
		return strings.TrimSuffix(string(out), "\r\n"), err
	case "darwin":
		out, err := commandOutput("pbpaste")
		return string(out), err
	default:
		if _, err := exec.LookPath("wl-paste"); err == nil {
			out, runErr := commandOutput("wl-paste", "--no-newline")
			return string(out), runErr
		}
		out, runErr := commandOutput("xclip", "-selection", "clipboard", "-o")
		return string(out), runErr
	}
}

func clipboardSet(text string) error {
	switch runtime.GOOS {
	case "windows":
		_, err := runPowerShell("$ErrorActionPreference='Stop'; $input | Set-Clipboard", text)
		return err
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd := exec.Command("wl-copy")
			cmd.Stdin = strings.NewReader(text)
			return cmd.Run()
		}
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
}

func performInput(args inputArgs) error {
	if args.Action == "" {
		return errors.New("input action is required")
	}
	switch runtime.GOOS {
	case "windows":
		return performWindowsInput(args)
	case "darwin":
		return performMacInput(args)
	default:
		return performLinuxInput(args)
	}
}

func performWindowsInput(args inputArgs) error {
	switch args.Action {
	case "text":
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait($env:PIPE_TEXT)")
		cmd.Env = append(os.Environ(), "PIPE_TEXT="+args.Text)
		return cmd.Run()
	case "key":
		keys, err := windowsSendKeys(args)
		if err != nil {
			return err
		}
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait($env:PIPE_KEYS)")
		cmd.Env = append(os.Environ(), "PIPE_KEYS="+keys)
		return cmd.Run()
	case "move", "click", "scroll":
		return runWindowsMouse(args)
	default:
		return fmt.Errorf("unsupported Windows input action: %s", args.Action)
	}
}

func windowsSendKeys(args inputArgs) (string, error) {
	key := args.Key
	if key == "" {
		return "", errors.New("key is required")
	}
	keyMap := map[string]string{"enter": "{ENTER}", "tab": "{TAB}", "esc": "{ESC}", "escape": "{ESC}", "backspace": "{BACKSPACE}", "delete": "{DELETE}", "space": " ", "left": "{LEFT}", "right": "{RIGHT}", "up": "{UP}", "down": "{DOWN}", "f1": "{F1}", "f2": "{F2}", "f3": "{F3}", "f4": "{F4}", "f5": "{F5}", "f6": "{F6}", "f7": "{F7}", "f8": "{F8}", "f9": "{F9}", "f10": "{F10}", "f11": "{F11}", "f12": "{F12}"}
	if mapped, ok := keyMap[strings.ToLower(key)]; ok {
		key = mapped
	} else if len([]rune(key)) != 1 {
		return "", fmt.Errorf("unsupported Windows key: %s", key)
	}
	prefix := ""
	for _, modifier := range args.Modifiers {
		switch strings.ToLower(strings.TrimSpace(modifier)) {
		case "ctrl", "control":
			prefix += "^"
		case "alt":
			prefix += "%"
		case "shift":
			prefix += "+"
		default:
			return "", fmt.Errorf("unsupported modifier: %s", modifier)
		}
	}
	return prefix + key, nil
}

func runWindowsMouse(args inputArgs) error {
	code := `Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class PipeMouse {
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int X,int Y);
 [DllImport("user32.dll")] public static extern void mouse_event(uint flags,uint dx,uint dy,uint data,UIntPtr extra);
}
'@; $x=[int]$env:PIPE_X; $y=[int]$env:PIPE_Y; if($env:PIPE_HAS_POS -eq '1'){[PipeMouse]::SetCursorPos($x,$y)|Out-Null}; if($env:PIPE_ACTION -eq 'click'){ $f=if($env:PIPE_BUTTON -eq 'right'){0x0008}else{0x0002}; [PipeMouse]::mouse_event($f,0,0,0,[UIntPtr]::Zero); [PipeMouse]::mouse_event(($f -shl 1),0,0,0,[UIntPtr]::Zero) } elseif($env:PIPE_ACTION -eq 'scroll'){ [PipeMouse]::mouse_event(0x0800,0,0,[uint32][int]$env:PIPE_AMOUNT,[UIntPtr]::Zero) }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", code)
	cmd.Env = append(os.Environ(), "PIPE_ACTION="+args.Action, "PIPE_X="+strconv.Itoa(args.X), "PIPE_Y="+strconv.Itoa(args.Y), "PIPE_AMOUNT="+strconv.Itoa(args.Amount), "PIPE_BUTTON="+args.Button)
	if args.Action == "move" || args.Action == "click" {
		cmd.Env = append(cmd.Env, "PIPE_HAS_POS=1")
	} else {
		cmd.Env = append(cmd.Env, "PIPE_HAS_POS=0")
	}
	return cmd.Run()
}

func performLinuxInput(args inputArgs) error {
	if _, err := exec.LookPath("xdotool"); err != nil {
		return errors.New("xdotool is required for Linux keyboard and mouse input")
	}
	switch args.Action {
	case "move":
		return exec.Command("xdotool", "mousemove", strconv.Itoa(args.X), strconv.Itoa(args.Y)).Run()
	case "click":
		if args.X != 0 || args.Y != 0 {
			if err := exec.Command("xdotool", "mousemove", strconv.Itoa(args.X), strconv.Itoa(args.Y)).Run(); err != nil {
				return err
			}
		}
		button := map[string]string{"left": "1", "middle": "2", "right": "3"}[args.Button]
		if button == "" {
			return fmt.Errorf("unsupported mouse button: %s", args.Button)
		}
		return exec.Command("xdotool", "click", button).Run()
	case "scroll":
		direction := "5"
		if args.Amount > 0 {
			direction = "4"
		}
		count := args.Amount
		if count < 0 {
			count = -count
		}
		if count == 0 {
			return errors.New("scroll amount must not be zero")
		}
		clicks := count / 120
		if clicks == 0 {
			clicks = 1
		}
		for i := 0; i < clicks; i++ {
			if err := exec.Command("xdotool", "click", direction).Run(); err != nil {
				return err
			}
		}
		return nil
	case "key":
		keys := append([]string{}, args.Modifiers...)
		keys = append(keys, args.Key)
		return exec.Command("xdotool", "key", strings.Join(keys, "+")).Run()
	case "text":
		return exec.Command("xdotool", "type", "--", args.Text).Run()
	default:
		return fmt.Errorf("unsupported Linux input action: %s", args.Action)
	}
}

func performMacInput(args inputArgs) error {
	switch args.Action {
	case "text":
		return exec.Command("osascript", "-e", fmt.Sprintf(`tell application "System Events" to keystroke %q`, args.Text)).Run()
	case "key":
		return exec.Command("osascript", "-e", fmt.Sprintf(`tell application "System Events" to keystroke %q`, args.Key)).Run()
	default:
		return errors.New("macOS mouse input requires cliclick; install it and extend performMacInput")
	}
}

func init() {
	// Make Ctrl+C stop the long-running relay/agent cleanly when possible.
	signal.Ignore(syscall.SIGPIPE)
}

const localAPIMarkdown = "# computer-pipe 局域网 API\n\n目标地址示例: http://192.168.1.20:17602\n\n## 认证\n\n接口统一使用一个请求头:\n\n    Authorization: Bearer PIPE_TOKEN\n\n首页、/docs、/docs.md 不需要认证。\n\n## 接口\n\n| 方法 | 路径 | 说明 |\n| --- | --- | --- |\n| GET | /api/v1/health | 主机信息 |\n| POST | /api/v1/command | 执行命令 |\n| GET | /api/v1/snapshot?monitor=0 | 返回 PNG 截图 |\n| GET | /api/v1/clipboard | 读取剪切板 |\n| POST | /api/v1/clipboard | 写入剪切板 |\n| POST | /api/v1/input | 键鼠输入 |\n| GET | /api/v1/help | JSON 接口说明 |\n\n## 示例\n\n    curl -H \"Authorization: Bearer PIPE_TOKEN\" http://192.168.1.20:17602/api/v1/health\n\n    curl -X POST -H \"Authorization: Bearer PIPE_TOKEN\" -H \"Content-Type: application/json\" -d '{\"command\":\"git status\",\"timeout\":120}' http://192.168.1.20:17602/api/v1/command\n\n    curl -o screen.png -H \"Authorization: Bearer PIPE_TOKEN\" http://192.168.1.20:17602/api/v1/snapshot\n\n    curl -X POST -H \"Authorization: Bearer PIPE_TOKEN\" -H \"Content-Type: application/json\" -d '{\"action\":\"key\",\"key\":\"c\",\"modifiers\":[\"ctrl\"]}' http://192.168.1.20:17602/api/v1/input\n"
const adminDashboardPageV2 = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>computer-pipe 管理台</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;color:#152238;background:#f3f6fb}
*{box-sizing:border-box}body{margin:0}button,input{font:inherit}
.shell{min-height:100vh;display:flex}.side{width:238px;background:#111d31;color:#dbe7ff;padding:24px 16px;display:flex;flex-direction:column}
.brand{font-size:20px;font-weight:750;letter-spacing:-.04em;padding:0 12px 28px}.brand small{display:block;margin-top:6px;color:#7e94b7;font-size:11px;font-weight:500;letter-spacing:.04em}
.nav{display:grid;gap:6px}.nav button{border:0;border-radius:10px;padding:11px 12px;background:transparent;color:#9eafcb;text-align:left;cursor:pointer}.nav button:hover{background:#1b2d4c;color:#fff}.nav button.active{background:#2c65df;color:#fff;font-weight:700}
.side-foot{margin-top:auto;padding:12px;color:#7087aa;font-size:11px;line-height:1.6}.main{flex:1;min-width:0;padding:28px 32px 48px}.top{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;margin-bottom:24px}.eyebrow{color:#6e83a1;font-size:11px;letter-spacing:.18em;font-weight:700}.top h1{margin:6px 0 0;font-size:29px;letter-spacing:-.05em}.top p{margin:7px 0 0;color:#738198}.top-actions{display:flex;gap:8px}.btn{border:0;border-radius:9px;padding:9px 13px;background:#2e68e5;color:#fff;cursor:pointer}.btn.secondary{background:#e9effb;color:#2b5ec5}.btn.danger{background:#fff0f1;color:#c73646}.btn:disabled{opacity:.45;cursor:not-allowed}
.panel{display:none}.panel.active{display:block}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:16px}.stat,.card{background:#fff;border:1px solid #e3e9f2;border-radius:15px;box-shadow:0 9px 24px #1a31520a}.stat{padding:17px 19px}.stat span{color:#7a879a;font-size:12px}.stat strong{display:block;font-size:28px;letter-spacing:-.05em;margin-top:7px}.stat small{color:#9aa6b7}.card{padding:20px;margin-bottom:16px}.card h2{font-size:18px;margin:0 0 7px;letter-spacing:-.03em}.muted{color:#77859a;font-size:13px}.token{display:flex;align-items:center;gap:9px;padding:12px;background:#f4f7fb;border-radius:10px}.token code{flex:1;overflow:auto;white-space:nowrap;color:#34445d}.copy{border:0;border-radius:7px;padding:6px 9px;background:#e5edff;color:#2e60c5;cursor:pointer;white-space:nowrap}.device-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.device{padding:17px;border:1px solid #e5eaf2;border-radius:13px;background:#fbfcfe}.device-head{display:flex;justify-content:space-between;gap:12px}.device-title{display:flex;gap:10px;align-items:center}.avatar{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;background:#e8efff;color:#2d65d6;font-weight:750}.name{font-weight:750}.host{margin-top:3px;color:#7b889b;font-size:12px}.pill{display:inline-flex;gap:5px;align-items:center;padding:5px 8px;border-radius:99px;font-size:11px;font-weight:700}.pill:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}.online{background:#e7f8f0;color:#15956a}.offline{background:#eef1f5;color:#8793a5}.meta{display:flex;gap:15px;margin:16px 0;color:#77859a;font-size:11px}.meta strong{display:block;color:#25334a;margin-top:3px;font-size:12px}.note{width:100%;border:1px solid #e1e7ef;border-radius:8px;padding:8px;background:#fff}.device-line{margin-top:10px}.device-line label{display:block;color:#77859a;font-size:11px;margin-bottom:5px}.device-line code{display:block;padding:8px;background:#f1f4f8;border-radius:8px;color:#465771;font-size:11px;white-space:nowrap;overflow:auto}.actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.actions .btn{font-size:12px;padding:8px 10px}.empty{border:1px dashed #d6deea;border-radius:12px;padding:45px;text-align:center;color:#78869a}.docs-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.docs-grid .card{margin:0}.docs-grid pre{margin:10px 0 0;white-space:pre-wrap;word-break:break-word;background:#101a2a;color:#dce7fb;padding:13px;border-radius:9px;line-height:1.55;font-size:12px}.endpoint{padding:10px 0;border-bottom:1px solid #edf0f5}.endpoint:last-child{border:0}.method{display:inline-block;width:48px;color:#2e68e5;font-size:11px;font-weight:750}.endpoint code{color:#364866}.field{display:flex;gap:9px;align-items:center;margin-top:12px}.field input{flex:1;border:1px solid #d9e1ec;border-radius:8px;padding:10px}.result{margin-top:12px;padding:11px;background:#f4f7fb;border-radius:9px;white-space:pre-wrap;color:#506078;font-size:12px;min-height:18px}.link-card{display:flex;justify-content:space-between;align-items:center;gap:14px}.link-card a{color:#2e68e5;text-decoration:none;font-weight:700}
@media(max-width:900px){.side{width:198px}.main{padding:22px 18px}.device-grid,.docs-grid{grid-template-columns:1fr}}
@media(max-width:640px){.shell{display:block}.side{width:auto;padding:16px}.brand{padding-bottom:14px}.nav{grid-template-columns:repeat(2,1fr)}.side-foot{display:none}.main{padding:18px 12px}.top{display:block}.top-actions{margin-top:14px}.stats{grid-template-columns:1fr}.card{padding:16px}}
.docs-title{display:flex;justify-content:space-between;align-items:center;gap:12px}.docs-title h2{margin:0}
</style>
</head>
<body>
<div class="shell">
<aside class="side"><div class="brand">computer-pipe<small>REMOTE CONTROL CENTER</small></div><nav class="nav"><button class="active" data-view="overview">概览</button><button data-view="devices">设备管理</button><button data-view="api">接口文档</button><button data-view="deploy">部署中心</button><button data-view="security">安全设置</button></nav><div class="side-foot">连接状态每 5 秒自动同步<br>所有设备调用均经过服务器鉴权</div></aside>
<main class="main">
<div class="top"><div><div class="eyebrow">CONTROL CENTER</div><h1>远程设备中心</h1><p>统一查看设备状态、凭证和调用入口</p></div><div class="top-actions"><button class="btn secondary" id="refresh">刷新</button><button class="btn" id="logout">退出</button></div></div>
<section class="panel active" data-panel="overview"><div class="stats"><div class="stat"><span>在线设备</span><strong id="onlineCount">—</strong><small>可立即调用</small></div><div class="stat"><span>已登记设备</span><strong id="totalCount">—</strong><small>包括离线设备</small></div><div class="stat"><span>最近同步</span><strong id="syncTime">—</strong><small>自动更新</small></div></div><div class="card"><h2>服务器 API 凭证</h2><p class="muted">用于查询设备和转发设备接口。</p><div class="token"><code id="serverToken">加载中</code><button class="copy" data-copy="serverToken">复制</button></div></div><div class="card link-card"><div><h2>设备调用信息</h2><p class="muted">每台设备有独立 Token 和专属服务器调用地址。</p></div><button class="btn secondary" data-view-link="devices">查看设备</button></div></section>
<section class="panel" data-panel="devices"><div class="card"><h2>设备管理</h2><p class="muted">设备 Token、系统信息、备注和转发地址集中在设备卡片中。</p><div id="devices" class="device-grid"><div class="empty">正在加载设备</div></div></div><div class="card"><h2>操作结果</h2><div id="result" class="result"></div></div></section>
<section class="panel" data-panel="api"><div class="card"><div class="docs-title"><h2>服务器管理接口</h2><button class="btn secondary" id="copyApiMarkdown">复制MD文档</button></div><p class="muted">统一请求头为 <code>Authorization: Bearer SERVER_API_TOKEN</code>。</p><div class="endpoint"><span class="method">GET</span><code>/manage/api/config</code><div class="muted">读取服务器 API Token 和部署入口</div></div><div class="endpoint"><span class="method">GET</span><code>/manage/api/devices</code><div class="muted">查看设备名称、在线状态、系统信息、备注、设备 Token 和调用地址</div></div><div class="endpoint"><span class="method">GET</span><code>/manage/api/help</code><div class="muted">返回机器可读接口说明</div></div><div class="endpoint"><span class="method">POST</span><code>/manage/api/device-token</code><div class="muted">为设备名生成新的设备级 Token</div></div></div><div class="docs-grid"><div class="card"><h2>设备转发接口</h2><p class="muted">把 <code>{name}</code> 替换为设备名称，接口由服务器转发到目标设备。</p><div class="endpoint"><span class="method">GET</span><code>/manage/api/devices/{name}/health</code></div><div class="endpoint"><span class="method">POST</span><code>/manage/api/devices/{name}/command</code></div><div class="endpoint"><span class="method">GET</span><code>/manage/api/devices/{name}/snapshot</code></div><div class="endpoint"><span class="method">GET/POST</span><code>/manage/api/devices/{name}/clipboard</code></div><div class="endpoint"><span class="method">POST</span><code>/manage/api/devices/{name}/input</code></div><div class="endpoint"><span class="method">POST</span><code>/manage/api/devices/{name}/uninstall</code></div></div><div class="card"><h2>调用示例</h2><pre id="apiExamples">加载中</pre></div></div></section>
<section class="panel" data-panel="deploy"><div class="card"><h2>部署中心</h2><p class="muted">生成带设备级 Token 的一键部署命令。</p><div class="link-card"><span>打开部署页面</span><a href="/deploy" target="_blank">/deploy ↗</a></div></div><div class="card"><h2>部署参数</h2><p class="muted">只需要选择内网直连或外网 relay，服务器地址、证书和下载地址自动带入。</p></div></section>
<section class="panel" data-panel="security"><div class="card"><h2>安全设置</h2><p class="muted">登录密码修改后立即生效。</p><div class="field"><input id="currentPassword" type="password" placeholder="当前密码"><input id="newPassword" type="password" placeholder="新密码"><button class="btn" id="changePassword">保存</button></div><div id="passwordMessage" class="result"></div></div><div class="card"><h2>接口鉴权</h2><p class="muted">管理接口使用服务器 API Token，设备接口使用对应设备 Token。</p></div></section>
</main></div>
<script>
const $=id=>document.getElementById(id);
const esc=value=>String(value==null?'':value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const base=location.origin;
function buildApiMarkdown(){const token=$('serverToken').textContent||'SERVER_API_TOKEN';const inline=String.fromCharCode(96);return ['# computer-pipe 服务器接口','','基础地址: '+base,'','## 认证','','请求头: '+inline+'Authorization: Bearer '+token+inline,'','## 服务器管理接口','','| 方法 | 路径 | 说明 |','| --- | --- | --- |','| GET | /manage/api/config | 读取服务器配置 |','| GET | /manage/api/devices | 查看设备、状态、系统信息、备注、设备 Token 和调用地址 |','| GET | /manage/api/help | 返回机器可读接口说明 |','| POST | /manage/api/device-token | 生成设备级 Token，参数为 name |','','## 设备转发接口','','| 方法 | 路径 | 说明 |','| --- | --- | --- |','| GET | /manage/api/devices/{name}/health | 健康检查 |','| POST | /manage/api/devices/{name}/command | 执行命令 |','| GET | /manage/api/devices/{name}/snapshot | 获取截图 |','| GET/POST | /manage/api/devices/{name}/clipboard | 读取或写入剪切板 |','| POST | /manage/api/devices/{name}/input | 键鼠输入 |','| POST | /manage/api/devices/{name}/uninstall | 卸载设备 |','','## 调用示例','',''+inline+'sh'+inline,'curl -k -H "Authorization: Bearer '+token+'" '+base+'/manage/api/devices/设备名/health','','curl -k -X POST -H "Authorization: Bearer '+token+'" -H "Content-Type: application/json" -d '+String.fromCharCode(39)+'{"command":"hostname","timeout":30}'+String.fromCharCode(39)+' '+base+'/manage/api/devices/设备名/command','','curl -k -o screen.png -H "Authorization: Bearer '+token+'" '+base+'/manage/api/devices/设备名/snapshot','',''+inline+''+''].join('\n')}
async function request(path,options){const response=await fetch(path,options||{});if(response.status===401){location.href='/';throw new Error('登录已失效')}const text=await response.text();let body={};try{body=JSON.parse(text)}catch(_){body={raw:text}}if(!response.ok)throw new Error(body.error||body.raw||'请求失败');return body}
function showResult(value){$('result').textContent=typeof value==='string'?value:JSON.stringify(value,null,2)}
function copy(value,button){if(navigator.clipboard){navigator.clipboard.writeText(value)}button.textContent='已复制';setTimeout(()=>button.textContent='复制',1200)}
function renderDevices(devices){$('onlineCount').textContent=devices.filter(d=>d.online).length;$('totalCount').textContent=devices.length;$('syncTime').textContent=new Date().toLocaleTimeString();if(!devices.length){$('devices').innerHTML='<div class="empty">暂无已接入设备</div>';return}$('devices').innerHTML=devices.map(d=>{const encoded=encodeURIComponent(d.name);const endpoint=base+'/manage/api/devices/'+encoded;const token=d.token||'暂无';return '<article class="device"><div class="device-head"><div class="device-title"><div class="avatar">'+esc((d.name||'?').slice(0,1).toUpperCase())+'</div><div><div class="name">'+esc(d.name)+'</div><div class="host">'+esc(d.hostname||'未知主机')+'</div></div></div><span class="pill '+(d.online?'online':'offline')+'">'+(d.online?'在线':'离线')+'</span></div><div class="meta"><div>系统<strong>'+esc(d.os||'—')+'</strong></div><div>架构<strong>'+esc(d.arch||'—')+'</strong></div><div>最后连接<strong>'+esc(d.last_seen?new Date(d.last_seen).toLocaleString():'—')+'</strong></div></div><input class="note" data-note="'+esc(d.name)+'" value="'+esc(d.note||'')+'" placeholder="添加设备备注"><div class="device-line"><label>设备 Token</label><div class="token"><code>'+esc(token)+'</code><button class="copy" data-value="'+esc(token)+'">复制</button></div></div><div class="device-line"><label>服务器调用地址</label><code>'+esc(endpoint)+'</code></div><div class="actions"><button class="btn secondary" data-action="health" data-name="'+esc(d.name)+'">健康检查</button><button class="btn secondary" data-action="snapshot" data-url="'+esc(endpoint+'/snapshot')+'">查看截图</button><button class="btn secondary" data-action="save-note" data-name="'+esc(d.name)+'">保存备注</button>'+(d.online?'<button class="btn danger" data-action="uninstall" data-name="'+esc(d.name)+'">卸载设备</button>':'')+'</div></article>'}).join('')}
async function load(){try{const data=await request('/manage/api/devices');renderDevices(data.devices||[]);const config=await request('/manage/api/config');$('serverToken').textContent=config.api_token;const example='curl -H "Authorization: Bearer '+config.api_token+'" '+base+'/manage/api/devices/设备名/health\\n\\ncurl -X POST -H "Authorization: Bearer '+config.api_token+'" -H "Content-Type: application/json" -d "{\\"command\\":\\"hostname\\",\\"timeout\\":30}" '+base+'/manage/api/devices/设备名/command\\n\\ncurl -o screen.png -H "Authorization: Bearer '+config.api_token+'" '+base+'/manage/api/devices/设备名/snapshot';$('apiExamples').textContent=example}catch(error){showResult(error.message)}}
document.querySelectorAll('[data-view]').forEach(button=>button.onclick=()=>{document.querySelectorAll('[data-view]').forEach(item=>item.classList.toggle('active',item===button));document.querySelectorAll('[data-panel]').forEach(panel=>panel.classList.toggle('active',panel.dataset.panel===button.dataset.view))});
document.querySelectorAll('[data-view-link]').forEach(button=>button.onclick=()=>document.querySelector('[data-view="devices"]').click());
document.body.addEventListener('click',async event=>{const copyButton=event.target.closest('.copy');if(copyButton){copy(copyButton.dataset.value||$('serverToken').textContent,copyButton);return}const button=event.target.closest('[data-action]');if(!button)return;try{const name=encodeURIComponent(button.dataset.name||'');if(button.dataset.action==='health'){showResult(await request('/manage/api/devices/'+name+'/health'));return}if(button.dataset.action==='snapshot'){window.open(button.dataset.url,'_blank');return}if(button.dataset.action==='save-note'){const input=Array.from(document.querySelectorAll('[data-note]')).find(item=>item.dataset.note===button.dataset.name);await request('/manage/api/devices/'+name+'/note',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note:input?input.value:''})});showResult('备注已保存');return}if(button.dataset.action==='uninstall'){if(!confirm('确认卸载 '+button.dataset.name+'？'))return;await request('/manage/api/devices/'+name+'/uninstall',{method:'POST'});showResult('卸载请求已发送');setTimeout(load,800)}}catch(error){showResult(error.message)}});
$('copyApiMarkdown').onclick=async()=>{try{await navigator.clipboard.writeText(buildApiMarkdown());$('copyApiMarkdown').textContent='已复制';setTimeout(()=>$('copyApiMarkdown').textContent='复制MD文档',1200)}catch(error){$('copyApiMarkdown').textContent='复制失败';setTimeout(()=>$('copyApiMarkdown').textContent='复制MD文档',1600)}};$('refresh').onclick=load;$('logout').onclick=async()=>{await fetch('/manage/api/logout',{method:'POST'});location.href='/'};$('changePassword').onclick=async()=>{try{await request('/manage/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:$('currentPassword').value,new_password:$('newPassword').value})});$('passwordMessage').textContent='密码已更新'}catch(error){$('passwordMessage').textContent=error.message}};load();setInterval(load,5000);
</script></body></html>`
