//go:build !windows

package susshd

import (
	"net"
	"os/exec"
	"syscall"

	"github.com/gliderlabs/ssh"
)

func setSysProcAttr(cmd *exec.Cmd, isPty bool) {
	if isPty {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid:  true,
			Setctty: true,
		}
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
	}
}

func NewAgentListener(_ string) (net.Listener, string, error) {
	l, err := ssh.NewAgentListener()
	if err != nil {
		return nil, "", err
	}
	return l, l.Addr().String(), nil
}
