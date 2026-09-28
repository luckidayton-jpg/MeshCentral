package evilginx

import (
	"encoding/json"
	"strings"
	"testing"
)

// The device grid answered 502 for every request, and the reason turned out to be the
// reply's shape rather than anything about the agents: MeshCentral's control protocol
// carries getDeviceDetails' payload as a JSON *string*, so the device array arrives
// double-encoded. json.RawMessage kept the quotes, the array parser failed, and
// "no agents have connected yet" was indistinguishable from "this cannot read the
// reply at all" -- the same answer for both, on a fresh install and a busy one.
//
// The four bytes below are what actually arrived from MeshCentral 1.2.5 with an empty
// grid, taken from the live server. Everything else here is either that observation or
// the inner shape parseDeviceArray already documented, not a guess at a new format.

func TestParseDeviceDetails_UnwrapsTheDoubleEncodedStringMeshCentralSends(t *testing.T) {
	// The observed empty-grid reply, byte for byte.
	devs, err := parseDeviceDetails([]byte(`{"action":"getDeviceDetails","data":"[]"}`))
	if err != nil {
		t.Fatalf("an empty grid failed to parse: %v. This is the exact reply the live "+
			"server sent, and failing here is what made the device grid a permanent 502.",
			err)
	}
	if len(devs) != 0 {
		t.Errorf("an empty grid parsed as %d devices: %+v", len(devs), devs)
	}
}

func TestParseDeviceDetails_AnEmptyGridIsAnEmptySliceNotNil(t *testing.T) {
	devs, err := parseDeviceDetails([]byte(`{"action":"getDeviceDetails","data":"[]"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Nil here is what serialised as "devices":null and made the xRAT page throw
	// rather than show "no agents yet".
	if devs == nil {
		t.Error("an empty grid parsed as a nil slice, which serialises as null")
	}
	// And it must survive the round trip to JSON as [].
	b, _ := json.Marshal(devs)
	if string(b) != "[]" {
		t.Errorf("an empty grid marshalled as %s, want []", b)
	}
}

func TestParseDeviceDetails_ReadsDevicesOutOfTheDoubleEncodedForm(t *testing.T) {
	// Same envelope, one device inside the string, using the node/lastConnect shape
	// parseDeviceArray already documents.
	inner := `[{"node":{"_id":"node//@abc","name":"laptop","host":"mac.local",` +
		`"osdesc":"macOS","ip":"10.0.0.5","meshid":"mesh//@abc","conn":3,"pwr":1},` +
		`"lastConnect":{"connecttime":1790600000}}]`
	reply, err := json.Marshal(map[string]string{"action": "getDeviceDetails", "data": inner})
	if err != nil {
		t.Fatalf("building the fixture: %v", err)
	}

	devs, err := parseDeviceDetails(reply)
	if err != nil {
		t.Fatalf("a populated grid failed to parse: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("got %d devices, want 1: %+v", len(devs), devs)
	}
	d := devs[0]
	if d.ID != "node//@abc" || d.Name != "laptop" || d.Hostname != "mac.local" {
		t.Errorf("the device did not survive the double unwrap: %+v", d)
	}
	if d.OS != "macOS" || d.IP != "10.0.0.5" || d.MeshId != "mesh//@abc" {
		t.Errorf("device fields were lost: %+v", d)
	}
	// conn=3 means connected; that bit is what the console colours.
	if !d.Online {
		t.Error("a device with conn=3 parsed as offline")
	}
	if d.LastConnect != 1790600000 {
		t.Errorf("last connect is %d, want 1790600000", d.LastConnect)
	}
}

// The raw form is still accepted. The encoding is a property of the server's protocol
// version, not something worth assuming away, and a future version that stops quoting
// the payload should keep working rather than break the grid.
func TestParseDeviceDetails_StillReadsTheUnquotedForm(t *testing.T) {
	raw := `{"action":"getDeviceDetails","data":[{"node":{"_id":"node//@x","name":"x","conn":1}}]}`
	devs, err := parseDeviceDetails([]byte(raw))
	if err != nil {
		t.Fatalf("the unquoted form stopped working: %v", err)
	}
	if len(devs) != 1 || devs[0].ID != "node//@x" {
		t.Errorf("the unquoted form parsed as %+v", devs)
	}
}

// A reply that is genuinely unreadable must still say so, and must not be mistaken for
// an empty grid. "No devices" and "could not read the reply" are different answers and
// the console shows them differently.
func TestParseDeviceDetails_UnreadableIsAnErrorNotAnEmptyGrid(t *testing.T) {
	_, err := parseDeviceDetails([]byte(`{"action":"getDeviceDetails","data":"not json"}`))
	if err == nil {
		t.Fatal("a data field that is not JSON parsed without error")
	}
	if !strings.Contains(err.Error(), "getDeviceDetails") {
		t.Errorf("the error does not name the command that failed: %v", err)
	}
}

// The description exists so a future shape change is diagnosable from the journal
// alone, which is the only place it can be read from: Cloudflare replaces the body of
// an origin 5xx with its own page.
func TestDescribeUnparsedReply_SaysEnoughToTellShapesApart(t *testing.T) {
	cases := []struct {
		name, raw string
		want      []string
	}{
		{"an object", `{"alpha":1,"beta":2}`, []string{"top-level object keys", "alpha", "beta"}},
		{"an array", `[{"node":1,"other":2}]`, []string{"entries", "first has keys", "node"}},
		{"an empty array", `[]`, []string{"empty array"}},
		{"neither", `"[]"`, []string{"neither object nor array"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := describeUnparsedReply([]byte(tc.raw))
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("the description %q does not mention %q", got, w)
				}
			}
		})
	}
}
