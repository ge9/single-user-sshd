//go:build windows

package susshd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os/exec"

	"github.com/Microsoft/go-winio"
)

func setSysProcAttr(cmd *exec.Cmd, isPty bool) {
}

// returns the listener and the generated pipe path (e.g., `\\.\pipe\agent-xxxx`).
func NewAgentListener() (net.Listener, string, error) {
	const maxRetries = 5

	for i := 0; i < maxRetries; i++ {
		b := make([]byte, 16) // 128 bit entropy
		if _, err := rand.Read(b); err != nil {
			return nil, "", fmt.Errorf("failed to generate random bytes: %w", err)
		}

		pipePath := fmt.Sprintf(`\\.\pipe\agent-%s`, hex.EncodeToString(b))

		// ListenPipe creates a new named pipe instance with default security attributes
		l, err := winio.ListenPipe(pipePath, nil)
		if err == nil {
			return l, pipePath, nil
		}
	}

	return nil, "", errors.New("failed to create a unique agent named pipe after maximum retries")
}
