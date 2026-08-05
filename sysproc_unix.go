//go:build !windows

package susshd

import (
	"os/exec"
	"syscall"
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
