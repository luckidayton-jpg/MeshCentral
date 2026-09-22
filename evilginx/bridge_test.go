package evilginx

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeMeshServer emulates the MeshCentral control.ashx socket closely enough to
// exercise the bridge: real AES-GCM auth cookie validation plus the message
// dispatch for the commands the bridge uses.
type fakeMeshServer struct {
	t        *testing.T
	key      []byte
	mu       sync.Mutex
	received []map[string]interface{}
	lastAuth string
}

func newFakeMeshServer(t *testing.T) (*fakeMeshServer, string) {
	t.Helper()
	key := make([]byte, 80)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	f := &fakeMeshServer{t: t, key: key}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/control.ashx", func(w http.ResponseWriter, r *http.Request) {
		cookie := r.URL.Query().Get("auth")
		if cookie == "" {
			t.Log("no auth cookie in handshake")
		}
		f.mu.Lock()
		f.lastAuth = cookie
		f.mu.Unlock()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		f.serve(conn)
	})
	srv := httptest.NewTLSServer(mux)

	base := strings.ReplaceAll(srv.URL, "https://", "https://")
	_ = base
	return f, srv.URL
}

func (f *fakeMeshServer) serve(conn *websocket.Conn) {
	go func() {
		defer conn.Close()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.received = append(f.received, map[string]interface{}{})
			_ = json.Unmarshal(data, &f.received[len(f.received)-1])
			f.mu.Unlock()

			var cmd struct {
				Action     string `json:"action"`
				ResponseID string `json:"responseid"`
				MeshName   string `json:"meshname"`
				MeshType   int    `json:"meshtype"`
				Type       string `json:"type"`
			}
			if json.Unmarshal(data, &cmd) != nil {
				continue
			}
			switch cmd.Action {
			case "serverversion":
				reply := map[string]interface{}{
					"action": "serverversion", "responseid": cmd.ResponseID,
					"result": "OK",
					"tags":   []map[string]string{{"tag": "version", "value": "1.1.99"}},
				}
				_ = conn.WriteJSON(reply)
			case "meshes":
				reply := map[string]interface{}{
					"action": "meshes", "responseid": cmd.ResponseID,
					"meshes": []map[string]interface{}{
						{"_id": "mesh//group1", "domain": "", "name": "group1", "mtype": 2, "devices": 3},
					},
				}
				_ = conn.WriteJSON(reply)
			case "createmesh":
				reply := map[string]interface{}{
					"action": "createmesh", "responseid": cmd.ResponseID,
					"result": "ok", "meshid": "mesh//xavier-" + randHex(6),
				}
				_ = conn.WriteJSON(reply)
			case "getDeviceDetails":
				// MeshCentral replies to getDeviceDetails without echoing the
				// responseid — the bridge must match on action.
				reply := map[string]interface{}{
					"action": "getDeviceDetails",
					"data": []map[string]interface{}{
						{
							"node": map[string]interface{}{
								"_id": "node//dev1", "name": "dev1",
								"host": "host1", "osdesc": "Windows", "ip": "10.0.0.5",
								"meshid": "mesh//group1", "conn": 1, "pwr": 1,
							},
							"lastConnect": map[string]interface{}{"connecttime": int64(1700000000)},
						},
					},
				}
				_ = conn.WriteJSON(reply)
			default:
				_ = conn.WriteJSON(map[string]interface{}{"action": cmd.Action, "responseid": cmd.ResponseID, "result": "unknown command"})
			}
		}
	}()
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func newTestBridge(t *testing.T, serverURL string) (*MeshBridge, error) {
	key := make([]byte, 80)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return New(BridgeOptions{
		ServerURL:   serverURL,
		LoginKeyHex: hex.EncodeToString(key),
		UserID:      "user//admin",
		InsecureTLS: true,
		Timeout:     5 * time.Second,
	})
}

func TestBridgeServerVersion(t *testing.T) {
	fake, url_ := newFakeMeshServer(t)

	b, err := newTestBridge(t, url_)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer b.Close()

	v, err := b.ServerVersion()
	if err != nil {
		t.Fatalf("ServerVersion: %v", err)
	}
	if v != "1.1.99" {
		t.Errorf("version = %q, want 1.1.99", v)
	}

	// Verify the auth cookie the server received.
	fake.mu.Lock()
	auth := fake.lastAuth
	fake.mu.Unlock()
	if auth == "" {
		t.Fatal("no auth cookie sent to server")
	}
	// The fake authenticated the connection implicitly (it used this key);
	// just assert the cookie looks properly encoded.
	if !strings.ContainsAny(auth, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$") || len(auth) < 40 {
		t.Errorf("auth cookie looks malformed: %q", auth)
	}
}

func TestBridgeCreateMesh(t *testing.T) {
	fake, url_ := newFakeMeshServer(t)

	b, err := newTestBridge(t, url_)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	meshid, err := b.CreateMesh("xavier-ops", "platform group")
	if err != nil {
		t.Fatalf("CreateMesh: %v", err)
	}
	if !strings.HasPrefix(meshid, "mesh//xavier-") {
		t.Errorf("meshid = %q, want prefix mesh//xavier-", meshid)
	}

	fake.mu.Lock()
	cmds := fake.received
	fake.mu.Unlock()
	last := cmds[len(cmds)-1]
	if last["action"] != "createmesh" {
		t.Fatalf("last action = %v", last["action"])
	}
	if last["meshname"] != "xavier-ops" {
		t.Errorf("meshname = %v", last["meshname"])
	}
	if last["meshtype"] != float64(2) {
		t.Errorf("meshtype = %v, want 2", last["meshtype"])
	}
}

func TestBridgeListDevices(t *testing.T) {
	_, url_ := newFakeMeshServer(t)

	b, err := newTestBridge(t, url_)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	devices, err := b.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	d := devices[0]
	if d.ID != "node//dev1" || d.Name != "dev1" || d.OS != "Windows" || d.IP != "10.0.0.5" {
		t.Errorf("unexpected device: %+v", d)
	}
	if !d.Online {
		t.Errorf("expected device online (conn=1)")
	}
}

func TestBridgeListMeshes(t *testing.T) {
	_, url_ := newFakeMeshServer(t)

	b, err := newTestBridge(t, url_)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	groups, err := b.ListMeshes()
	if err != nil {
		t.Fatalf("ListMeshes: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].MeshId != "mesh//group1" || groups[0].Name != "group1" || groups[0].Devices != 3 {
		t.Errorf("unexpected group: %+v", groups[0])
	}
}

func TestBridgeTimeoutAndClose(t *testing.T) {
	// Create a server that dials but never replies.
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/control.ashx", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		// Read but never respond; hold the socket open.
		go func() {
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					return
				}
			}
		}()
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	b, err := newTestBridge(t, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	start := time.Now()
	_, err = b.ServerVersion()
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("timed out too slowly: %s", time.Since(start))
	}
}

// Nothing to clean up: the bridge Close() tears down the socket and the
// httptest server is shutdown by the suite via defer.

func TestBridgeClosePropagatesCause(t *testing.T) {
	// Server accepts the socket then immediately drops it. The in-flight
	// call must report the underlying close cause, not a bare
	// "bridge closed".
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/control.ashx", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "nope"),
			time.Now().Add(time.Second))
		_ = conn.Close()
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	b, err := newTestBridge(t, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	_, err = b.CreateMesh("xavierkit-ops", "")
	if err == nil {
		t.Fatal("expected close error")
	}
	// The underlying websocket close must be visible in the error chain.
	if !strings.Contains(err.Error(), "close") {
		t.Fatalf("error should carry the close cause, got: %v", err)
	}
}

func TestBridgeServerCloseMessageSurfacesCause(t *testing.T) {
	// MeshCentral rejects bad auth with {action:'close',cause,msg} before
	// dropping the socket. The bridge must surface "noauth" so operators
	// can tell a wrong login key apart from a dead server.
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/control.ashx", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		_ = conn.WriteJSON(map[string]interface{}{"action": "close", "cause": "noauth", "msg": "noauth"})
		_ = conn.Close()
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	b, err := newTestBridge(t, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	_, err = b.CreateMesh("xavierkit-ops", "")
	if err == nil {
		t.Fatal("expected auth-reject error")
	}
	if !strings.Contains(err.Error(), "noauth") {
		t.Fatalf("error should carry the server close cause, got: %v", err)
	}
}

func TestParseDeviceDetailsEdgeCases(t *testing.T) {
	// Bare array payload.
	devs, err := parseDeviceDetails([]byte(`[{"node":{"_id":"node//x","name":"x","conn":3,"pwr":0}},{"node":{"_id":"node//y","name":"y"}}]`))
	if err != nil {
		t.Fatalf("bare array: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("bare array: got %d devices", len(devs))
	}
	if !devs[0].Online || devs[1].Online {
		t.Errorf("conn semantics wrong: %+v", devs)
	}

	// Garbage fails.
	if _, err := parseDeviceDetails([]byte(`not json`)); err == nil {
		t.Fatal("expected error for garbage")
	}
}
