//go:build windows

package susshd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

func setSysProcAttr(cmd *exec.Cmd, isPty bool) {
}

type sockPlusListener struct {
	net.Listener
	sockPath  string
	cmd       *exec.Cmd
	closeOnce sync.Once
}

func (l *sockPlusListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.Listener.Close()

		if l.cmd != nil && l.cmd.Process != nil {
			_ = l.cmd.Process.Kill()
			_ = l.cmd.Wait()
		}

		if l.sockPath != "" {
			_ = os.Remove(l.sockPath)
		}
	})
	return err
}

func NewAgentListener(perlPath string) (net.Listener, string, error) {
	var pipeL net.Listener
	var rawPipeName, pipeName string
	var err error

	for i := 0; i < 5; i++ { //up to 5 tries
		randBuf := make([]byte, 4)
		_, _ = rand.Read(randBuf)
		randSuffix := hex.EncodeToString(randBuf)

		rawPipeName = fmt.Sprintf("susshd-%s", randSuffix)
		pipeName = fmt.Sprintf(`\\.\pipe\%s`, rawPipeName)

		pipeL, err = winio.ListenPipe(pipeName, nil)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if perlPath == "" { //we don't use cygwin unix socket
		return pipeL, pipeName, nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to listen pipe after 5 retries: %w", err)
	}

	tempDir := os.TempDir()
	susshdDir := filepath.Join(tempDir, "susshd")
	if err := os.MkdirAll(susshdDir, 0755); err != nil {
		pipeL.Close()
		return nil, "", fmt.Errorf("failed to create susshd directory: %w", err)
	}

	sockPath := filepath.Join(susshdDir, fmt.Sprintf("%s.sock", rawPipeName))
	winSockPath := filepath.ToSlash(sockPath)

	// get the path of npipe-proxy.pl
	execPath, err := os.Executable()
	if err != nil {
		pipeL.Close()
		os.Remove(sockPath)
		return nil, "", fmt.Errorf("failed to get executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)
	plPath := filepath.Join(execDir, "npipe-proxy.pl")

	cmd := exec.Command(perlPath, filepath.ToSlash(plPath), winSockPath, pipeName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		pipeL.Close()
		os.Remove(sockPath)
		return nil, "", fmt.Errorf("failed to start perl: %w", err)
	}

	// wait for socket file created
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return &sockPlusListener{
		Listener: pipeL,
		sockPath: sockPath,
		cmd:      cmd,
	}, pipeName, nil
}
