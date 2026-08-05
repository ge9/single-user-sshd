//go:build windows

package susshd

import "os/exec"

func setSysProcAttr(cmd *exec.Cmd, isPty bool) {
}
