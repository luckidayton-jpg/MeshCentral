package evilginx

import "testing"

// A node id is "node//<agent id>@<server id>". MeshCentral addresses a node by the agent
// id alone, and sending the whole thing back does not delete anything -- which looks
// exactly like the button not working.
func TestNodeAgentID_StripsThePrefixAndTheServerHalf(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{
			"a full node id",
			"node//w5ijcnDWxM1OyLPq73msXJqAqr8wV5jQfMDsmAUnJ2FOUVCzzVxg33J434myqWPj@kbijpG5iyMb3",
			"w5ijcnDWxM1OyLPq73msXJqAqr8wV5jQfMDsmAUnJ2FOUVCzzVxg33J434myqWPj",
		},
		{"an id with no server half", "node//abc", "abc"},
		{"surrounding whitespace", "  node//abc  ", "abc"},
		// Refused rather than half-parsed. An empty agent id would be sent to the
		// server as a deletion of nothing, which reads as success.
		{"not a node id", "mesh//@abc", ""},
		{"a bare name", "laptop", ""},
		{"the prefix with nothing after it", "node//", ""},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeAgentID(tc.in); got != tc.want {
				t.Errorf("nodeAgentID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Deleting a node is destructive and irreversible, so the id has to be validated
// before a message is sent. A malformed id must never reach MeshCentral.
func TestDeleteNode_RefusesAnIDThatIsNotANodeID(t *testing.T) {
	b := &MeshBridge{}
	// Connect is never reached: the id is rejected first. If it were not, the call
	// would fail on a nil websocket instead, which is a different failure and would
	// mean the validation is not happening.
	if err := b.DeleteNode("definitely-not-a-node"); err == nil {
		t.Fatal("DeleteNode accepted an id that is not a node id.\n" +
			"It is destructive and irreversible, so the shape has to be checked " +
			"before anything is sent.")
	}
}
