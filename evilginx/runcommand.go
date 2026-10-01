package evilginx

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Running a command on an agent is how the platform asks a device about itself, and
// two properties of MeshCentral's control protocol are not guessable and cost real
// time to find. Both are recorded here because the wire format is the only
// documentation and a wrong guess produces silence rather than an error.
//
//  1. `cmds` must be a STRING.
//
//	meshctrl.js sends cmds as an array, and reading meshuser.js that looks right:
//
//	    } else if (typeof command.cmds == 'string') {
//	        // Run provided commands
//	        if (command.cmds.length > 65535) return;
//	        processRunCommand(command);
//	    }
//
//	An array matches none of the four branches (presetcmd, cmdpath, cmds), so the
//	case falls out of the switch having done nothing at all. There is no error, no
//	"Unknown action" line in the server log, and no reply of any kind -- the request
//	just times out, looking exactly like an unreachable agent. Verified live: the same
//	request with cmds as a string replies {"result":"OK"} and the output arrives.
//
//  2. The reply carries no output. Command output arrives separately, as an
//     unsolicited console frame:
//
//	    {"action":"msg","type":"console","value":"hello\n","nodeid":"node//..."}
//
//	The reply to the action itself is only {"result":"OK"}. So a caller that waits for
//	the correlated reply and expects the output in it will always see "OK" and nothing
//	else, and a caller that ignores the reply has nothing to correlate on.

// consoleFrame is one line (or fragment) of command output.
type consoleFrame struct {
	NodeID string `json:"nodeid"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}

// consoleCollector gathers console frames for one run.
type consoleCollector struct {
	mu     sync.Mutex
	lines  []string
	done   chan struct{}
	closed bool
}

func (c *consoleCollector) add(f consoleFrame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.lines = append(c.lines, f.Value)
}

// finish stops collection. Later frames are dropped: an unbounded collector on a
// socket that stays open would grow forever.
func (c *consoleCollector) finish() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return strings.Join(c.lines, "")
}

// wait blocks until the server reports the run complete, or d elapses. The bool is
// false only on the timeout path, so a caller can tell "finished" from "gave up".
func (c *consoleCollector) wait(d time.Duration) (string, bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return strings.Join(c.lines, ""), true
	case <-timer.C:
		return c.finish(), false
	}
}

// RunShell executes a shell script on one agent and returns its combined output.
//
// nodeID is the full "node//<agent id>@<server id>" as ListDevices reports it;
// MeshCentral prefixes a bare id with the domain itself, so either form works.
//
// The script runs in a shell with no window server connection, which matters for
// anything that touches the display: screencapture answers "could not create image
// from display" and produces no file. That is a property of the context, not of
// permissions, and it is why this cannot be used to test whether Screen Recording is
// granted.
func (b *MeshBridge) RunShell(nodeID, script string) (string, error) {
	if strings.TrimSpace(script) == "" {
		return "", fmt.Errorf("evilginx: run shell: empty script")
	}
	agentID := nodeAgentID(nodeID)
	if agentID == "" {
		agentID = strings.TrimSpace(nodeID)
	}

	col := &consoleCollector{done: make(chan struct{})}
	b.addConsoleCollector(col)
	defer b.removeConsoleCollector(col)
	// The collector's done channel is closed once the server says the run finished,
	// so the wait ends on the real end of output rather than on a timeout. Without
	// this every call pays the full Timeout even on a command that finished in a
	// second -- a 45s wait for `id -u`.
	defer func() {
		col.mu.Lock()
		select {
		case <-col.done:
		default:
			close(col.done)
		}
		col.mu.Unlock()
	}()

	_, err := b.call("runcommands", map[string]interface{}{
		"nodeids": []string{agentID},
		"type":    3,      // 3 = Linux/BSD/macOS. meshuser.js maps 0 to 1 or 3 by agent type.
		"cmds":    script, // must be a string, not an array
	})
	if err != nil {
		return "", fmt.Errorf("evilginx: run shell on %s: %w", agentID, err)
	}

	out, complete := col.wait(b.opts.Timeout)
	if !complete {
		return out, fmt.Errorf("evilginx: run shell on %s: output did not complete within %s",
			agentID, b.opts.Timeout)
	}
	return out, nil
}

// RunShellTrimmed is RunShell with the server's own console framing removed.
//
// meshuser.js brackets the script with "Run commands (0): <script>" and closes with
// "Run commands completed." Those lines are the protocol talking, not the script, and
// leaving them in means every caller has to know to strip them -- which is how a
// parse quietly ends up matching the wrapper instead of the answer.
func (b *MeshBridge) RunShellTrimmed(nodeID, script string) (string, error) {
	raw, err := b.RunShell(nodeID, script)
	if err != nil {
		return raw, err
	}
	return stripConsoleFraming(raw), nil
}

// stripConsoleFraming removes the "Run commands (n): ..." banner and the
// "Run commands completed." footer. Both are matched on content rather than on
// position, because a script that prints its own text cannot be assumed to leave
// them at the ends.
func stripConsoleFraming(raw string) string {
	lines := strings.Split(raw, "\n")
	kept := make([]string, 0, len(lines))
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		trimmed = strings.TrimSuffix(trimmed, "\r")
		trimmed = strings.TrimSuffix(trimmed, "exit")
		trimmed = strings.TrimSpace(trimmed)
		if strings.HasPrefix(trimmed, "Run commands (") && strings.Contains(trimmed, "):") {
			continue
		}
		if strings.HasPrefix(trimmed, "Run commands completed") {
			continue
		}
		kept = append(kept, ln)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

func (b *MeshBridge) addConsoleCollector(c *consoleCollector) {
	b.consoleMu.Lock()
	b.consoleCollectors = append(b.consoleCollectors, c)
	b.consoleMu.Unlock()
}

func (b *MeshBridge) removeConsoleCollector(c *consoleCollector) {
	b.consoleMu.Lock()
	for i, existing := range b.consoleCollectors {
		if existing == c {
			b.consoleCollectors = append(b.consoleCollectors[:i], b.consoleCollectors[i+1:]...)
			break
		}
	}
	b.consoleMu.Unlock()
}

// completionMarker is what meshuser.js emits to close a run's output. The agent's
// console frames are the only signal that a command has finished: the action's own
// reply says "OK" the moment the command is dispatched, before any of it has run.
const completionMarker = "Run commands completed."

// deliverConsole hands a console frame to every open collector. Frames are broadcast
// rather than routed, because they carry no responseid and therefore nothing to
// correlate on; a run is identified by the nodeid it was issued against.
func (b *MeshBridge) deliverConsole(nodeID, value string) {
	b.consoleMu.Lock()
	snapshot := make([]*consoleCollector, len(b.consoleCollectors))
	copy(snapshot, b.consoleCollectors)
	b.consoleMu.Unlock()
	for _, c := range snapshot {
		c.add(consoleFrame{NodeID: nodeID, Type: "console", Value: value})
		if strings.Contains(value, completionMarker) {
			// Signal exactly once, and never under the lock a second close would
			// panic on: two runs finishing at the same instant both try this.
			c.mu.Lock()
			select {
			case <-c.done:
			default:
				close(c.done)
			}
			c.mu.Unlock()
		}
	}
}
