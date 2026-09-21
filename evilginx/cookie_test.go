package evilginx

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestEncodeDecodeAuthCookieRoundTrip(t *testing.T) {
	key := make([]byte, 80)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	userID := "user//admin"
	domainID := ""

	cookie, err := encodeAuthCookie(userID, domainID, key, now)
	if err != nil {
		t.Fatalf("encodeAuthCookie: %v", err)
	}
	if cookie == "" {
		t.Fatal("empty cookie")
	}

	decoded, err := decodeAuthCookie(cookie, key)
	if err != nil {
		t.Fatalf("decodeAuthCookie: %v", err)
	}
	if decoded["userid"] != userID {
		t.Errorf("userid = %q, want %q", decoded["userid"], userID)
	}
	if decoded["domainid"] != domainID {
		t.Errorf("domainid = %q, want %q", decoded["domainid"], domainID)
	}
	ts, ok := decoded["time"].(float64)
	if !ok {
		t.Fatalf("time not a number: %#v", decoded["time"])
	}
	if int64(ts) != now.Unix() {
		t.Errorf("time = %d, want %d", int64(ts), now.Unix())
	}

	// Wrong key must fail to authenticate.
	wrong := append([]byte{}, key...)
	wrong[0] ^= 0xff
	if _, err := decodeAuthCookie(cookie, wrong); err == nil {
		t.Fatal("decode with wrong key succeeded, want error")
	}
}

// TestWireLayoutMirrorsNode verifies the wire layout iv||authTag||ciphertext
// matches MeshCentral's decodeCookieAESGCM: the tag sits at bytes [12:28] and
// the total length is 28 + ciphertext length.
func TestWireLayoutMirrorsNode(t *testing.T) {
	key := make([]byte, 80)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	payload, err := json.Marshal(map[string]interface{}{
		"userid": "user//admin", "domainid": "", "time": now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := encodeAuthCookie("user//admin", "", key, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(replaceAll(replaceAll(cookie, '@', '+'), '$', '/'))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 28+len(payload) {
		t.Fatalf("cookie length = %d, want 28+%d=%d", len(raw), len(payload), 28+len(payload))
	}
	iv := raw[:12]
	if allZero(iv) {
		t.Fatal("IV is all zero")
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func TestLoginKeyFromHex(t *testing.T) {
	key := make([]byte, 80)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(key)
	k, err := loginKeyFromHex(h)
	if err != nil {
		t.Fatalf("loginKeyFromHex: %v", err)
	}
	if len(k) != 80 {
		t.Fatalf("key length = %d, want 80", len(k))
	}

	if _, err := loginKeyFromHex("zz"); err == nil {
		t.Fatal("non-hex key accepted")
	}
	if _, err := loginKeyFromHex("deadbeef"); err == nil {
		t.Fatal("too-short key accepted")
	}
}
