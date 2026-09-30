package evilginx

import "testing"

// A node id is "node//" followed by MeshCentral's own id for the node, which carries
// several "@"-separated segments. Everything after the prefix is the id; trimming it
// produces a value that matches no node, and the removal then silently does nothing.
func TestNodeAgentID_StripsThePrefixAndTheServerHalf(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		// The shape that actually occurs, and the one the first version got wrong.
		// Truncating at the first "@" yields "D1A1CCoc", which matches no node, so
		// the removal reported success and left the device in the grid.
		{
			"a node id with several @ segments",
			"node//D1A1CCoc@2k26dFvwyvguRqzEUeYnWVEkIhUWCSjF9isyAo4JIq@kbijpG5iyMb3",
			"D1A1CCoc@2k26dFvwyvguRqzEUeYnWVEkIhUWCSjF9isyAo4JIq@kbijpG5iyMb3",
		},
		{
			"a node id with one @ segment",
			"node//w5ijcnDWxM1OyLPq73msXJqAqr8wV5jQfMDsmAUnJ2FOUVCzzVxg33J434myqWPj@kbijpG5",
			"w5ijcnDWxM1OyLPq73msXJqAqr8wV5jQfMDsmAUnJ2FOUVCzzVxg33J434myqWPj@kbijpG5",
		},
		{"an id with no @ at all", "node//abc", "abc"},
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
