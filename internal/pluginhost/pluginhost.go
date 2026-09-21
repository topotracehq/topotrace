/*******************************************************************************
 * @file         pluginhost.go
 * @brief        Package pluginhost implements TopoTrace's out-of-process plugin mechanism: core launches each plugin as a subprocess, performs a stdout handshake, then talks to it over net/rpc via a Unix domain socket.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package pluginhost implements TopoTrace's out-of-process plugin
// mechanism: core launches each plugin as a subprocess, performs a
// stdout handshake, then talks to it over net/rpc via a Unix domain
// socket. See docs/plugins.md for the protocol and rationale.
//
// This is a first slice proving the mechanism end to end (see
// plugins/ai-governance), not a full plugin SDK: no third-party
// distribution, no auth between core and plugin (both run as the same
// local user, same trust boundary as any other subprocess this server
// launches), no hot-reload. It is deliberately small.
package pluginhost

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MagicCookie is the fixed string a plugin process must echo back in
// its handshake line to prove it's actually a TopoTrace plugin and not
// some unrelated executable that happened to be dropped in the plugin
// directory. Not a secret -- just a sanity check, the same role
// HashiCorp's go-plugin cookie env var plays.
const MagicCookie = "MUSTER_PLUGIN_MAGIC_COOKIE_V1"

// ProtocolVersion is the RPC protocol version this core speaks. A
// plugin reporting a different version is rejected rather than loaded
// half-compatible.
const ProtocolVersion = 1

// handshakeTimeout bounds how long the manager waits for a plugin's
// handshake line after launching it.
const handshakeTimeout = 10 * time.Second

// shutdownGrace bounds how long the manager waits for a plugin to exit
// after Shutdown before it kills the process.
const shutdownGrace = 3 * time.Second

// PluginInfo is what Describe returns: identity and the one HTTP
// capability this first slice supports.
type PluginInfo struct {
	Name        string // stable identifier, also the URL mount segment
	Version     string
	MountPrefix string // e.g. "ai-governance" -- mounted at /api/plugins/{MountPrefix}/
	Description string
}

// PluginHTTPRequest is one HTTP request bridged to the plugin. Path is
// relative to the plugin's mount point (no leading slash).
type PluginHTTPRequest struct {
	Method  string
	Path    string
	Query   string
	Headers map[string][]string
	Body    []byte
}

// PluginHTTPResponse is the plugin's answer to a PluginHTTPRequest.
type PluginHTTPResponse struct {
	Status  int
	Headers map[string][]string
	Body    []byte
}

// handshakeLine is the fixed-format line a plugin writes to its own
// stdout exactly once, on startup:
//
//	MUSTER_PLUGIN_MAGIC_COOKIE_V1|1|/path/to/socket
//
// cookie | protocol version | unix socket path
func parseHandshake(line string) (version int, sockPath string, err error) {
	parts := strings.Split(strings.TrimSpace(line), "|")
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("malformed handshake line %q: want 3 pipe-separated fields", line)
	}
	if parts[0] != MagicCookie {
		return 0, "", fmt.Errorf("bad magic cookie %q", parts[0])
	}
	version, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, "", fmt.Errorf("bad protocol version %q: %w", parts[1], err)
	}
	sockPath = parts[2]
	if sockPath == "" {
		return 0, "", fmt.Errorf("empty socket path in handshake")
	}
	return version, sockPath, nil
}

// HandshakeLine builds the line a plugin process should write to
// stdout. Plugins outside this repo can construct it by hand -- it's
// a fixed, documented format -- but this helper keeps in-repo plugins
// (like plugins/ai-governance) from having to restate it.
func HandshakeLine(sockPath string) string {
	return fmt.Sprintf("%s|%d|%s", MagicCookie, ProtocolVersion, sockPath)
}

// Plugin is one running plugin process and its RPC client.
type Plugin struct {
	Info PluginInfo

	path   string
	cmd    *exec.Cmd
	client *rpc.Client
	log    *slog.Logger
}

// Manager launches, mounts, and shuts down plugins found under Dir.
type Manager struct {
	Dir    string
	Logger *slog.Logger

	mu      sync.Mutex
	plugins []*Plugin
}

// NewManager returns a Manager for the given plugin directory. dir may
// be empty, in which case Load is a no-op (the default: plugins are
// opt-in).
func NewManager(dir string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{Dir: dir, Logger: logger}
}

// Load scans Dir for executable files, launches each as a plugin, and
// keeps the ones that complete the handshake. A plugin that fails to
// launch, handshake, or Describe is logged as a warning and skipped --
// this never returns an error that should abort server startup.
func (m *Manager) Load(ctx context.Context) {
	if m.Dir == "" {
		return
	}
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		m.Logger.Warn("plugin directory unreadable, skipping plugin load", "dir", m.Dir, "err", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Mode()&0111 == 0 {
			continue // not executable
		}
		path := filepath.Join(m.Dir, e.Name())
		p, err := m.launch(ctx, path)
		if err != nil {
			m.Logger.Warn("plugin failed to load", "path", path, "err", err)
			continue
		}
		m.mu.Lock()
		m.plugins = append(m.plugins, p)
		m.mu.Unlock()
		m.Logger.Info("plugin loaded", "name", p.Info.Name, "version", p.Info.Version, "mount", p.Info.MountPrefix, "path", path)
	}
}

func (m *Manager) launch(ctx context.Context, path string) (*Plugin, error) {
	cmd := exec.CommandContext(ctx, path)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}

	lineCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			lineCh <- scanner.Text()
			return
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
			return
		}
		errCh <- fmt.Errorf("plugin exited before writing a handshake line")
	}()

	var line string
	select {
	case line = <-lineCh:
	case err := <-errCh:
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("handshake: %w", err)
	case <-time.After(handshakeTimeout):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("handshake: timed out after %s waiting for handshake line", handshakeTimeout)
	}

	version, sockPath, err := parseHandshake(line)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if version != ProtocolVersion {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("handshake: protocol version %d unsupported (core speaks %d)", version, ProtocolVersion)
	}

	conn, err := dialWithRetry(sockPath, handshakeTimeout)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("dialing plugin socket %s: %w", sockPath, err)
	}
	client := jsonrpc.NewClient(conn)

	p := &Plugin{path: path, cmd: cmd, client: client, log: m.Logger.With("plugin_path", path)}

	var pi PluginInfo
	if err := client.Call("Plugin.Describe", struct{}{}, &pi); err != nil {
		_ = client.Close()
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("Describe: %w", err)
	}
	if pi.Name == "" || pi.MountPrefix == "" {
		_ = client.Close()
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("Describe returned incomplete PluginInfo: %+v", pi)
	}
	p.Info = pi
	return p, nil
}

// dialWithRetry handles the small race between a plugin creating its
// listening socket and this process attempting to connect: the
// handshake line is written right after the listener is created, but
// give it a brief grace window regardless.
func dialWithRetry(sockPath string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	return nil, lastErr
}

// List returns the currently-loaded plugins' info, for GET /api/plugins.
func (m *Manager) List() []PluginInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PluginInfo, 0, len(m.plugins))
	for _, p := range m.plugins {
		out = append(out, p.Info)
	}
	return out
}

// Mount registers each loaded plugin's HTTP capability on mux at
// /api/plugins/{name}/.
func (m *Manager) Mount(mux *http.ServeMux) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.plugins {
		p := p
		prefix := "/api/plugins/" + p.Info.MountPrefix + "/"
		mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			p.serveHTTP(w, r, prefix)
		})
	}
}

func (p *Plugin) serveHTTP(w http.ResponseWriter, r *http.Request, prefix string) {
	relPath := strings.TrimPrefix(r.URL.Path, prefix)
	body, err := readAll(r)
	if err != nil {
		http.Error(w, "reading request body", http.StatusInternalServerError)
		return
	}
	req := PluginHTTPRequest{
		Method:  r.Method,
		Path:    relPath,
		Query:   r.URL.RawQuery,
		Headers: r.Header,
		Body:    body,
	}
	var resp PluginHTTPResponse
	if err := p.client.Call("Plugin.HandleHTTP", req, &resp); err != nil {
		p.log.Error("plugin RPC call failed", "err", err)
		http.Error(w, "plugin error", http.StatusBadGateway)
		return
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(resp.Body)
}

func readAll(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}

// PluginServer is the plugin-side interface a plugin process registers
// over RPC. Plugins embed or implement this and pass it to ServePlugin.
type PluginServer interface {
	Describe(args struct{}, reply *PluginInfo) error
	HandleHTTP(req PluginHTTPRequest, reply *PluginHTTPResponse) error
	Shutdown(args struct{}, reply *struct{}) error
}

// ServePlugin is the plugin-side half of the protocol: it creates a
// Unix domain socket under a fresh temp path, writes the handshake
// line to stdout, and serves RPC requests on that socket using impl.
// It returns a channel that's closed once impl.Shutdown has been
// called over RPC -- a plugin's main() typically calls this and then
// blocks on the returned channel before exiting.
func ServePlugin(impl PluginServer) (<-chan struct{}, error) {
	sockDir, err := os.MkdirTemp("", "muster-plugin-*")
	if err != nil {
		return nil, fmt.Errorf("creating socket dir: %w", err)
	}
	sockPath := filepath.Join(sockDir, "plugin.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", sockPath, err)
	}

	done := make(chan struct{})
	wrapper := &shutdownNotifier{PluginServer: impl, listener: listener, sockDir: sockDir, done: done}

	server := rpc.NewServer()
	if err := server.RegisterName("Plugin", wrapper); err != nil {
		return nil, fmt.Errorf("registering RPC service: %w", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()

	// Write the handshake line only after the listener is live, so the
	// core never dials before the socket exists.
	fmt.Println(HandshakeLine(sockPath))

	return done, nil
}

// shutdownNotifier wraps a plugin's PluginServer so that, once its
// Shutdown RPC method has run, this process also closes the listener
// and signals ServePlugin's caller to exit.
type shutdownNotifier struct {
	PluginServer
	listener net.Listener
	sockDir  string
	done     chan struct{}
}

// Shutdown calls through to the wrapped implementation, then tears
// down the listener and signals done. Defined explicitly (rather than
// relying on the embedded PluginServer.Shutdown) so net/rpc's method
// dispatch runs this version.
func (s *shutdownNotifier) Shutdown(args struct{}, reply *struct{}) error {
	err := s.PluginServer.Shutdown(args, reply)
	_ = s.listener.Close()
	_ = os.RemoveAll(s.sockDir)
	close(s.done)
	return err
}

// Shutdown gracefully stops every loaded plugin: RPC Shutdown, then a
// grace period, then SIGKILL if it hasn't exited.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	plugins := append([]*Plugin(nil), m.plugins...)
	m.mu.Unlock()

	for _, p := range plugins {
		var reply struct{}
		if err := p.client.Call("Plugin.Shutdown", struct{}{}, &reply); err != nil {
			p.log.Warn("plugin Shutdown RPC failed", "err", err)
		}
		_ = p.client.Close()

		done := make(chan error, 1)
		go func(p *Plugin) { done <- p.cmd.Wait() }(p)
		select {
		case <-done:
		case <-time.After(shutdownGrace):
			p.log.Warn("plugin did not exit after Shutdown, killing")
			_ = p.cmd.Process.Kill()
			<-done
		}
	}
}
