package susshd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/charmbracelet/x/xpty"
	"github.com/engity-com/ssh-server-go"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

func BaseSSH(ctx context.Context, ln net.Listener, cmd_prefix string, acceptEnv []string, perlPath string, options ...ssh.Option) error {
	forwardHandler := &ssh.ForwardedTCPHandler{}
	forwardedUnixHandler := &ssh.ForwardedUnixHandler{}
	server := ssh.Server{
		Addr:              ln.Addr().String(),
		SubsystemHandlers: map[string]ssh.SubsystemHandler{"sftp": SftpHandler},
		Handler: func(s ssh.Session) error {
			cmd := exec.Command(cmd_prefix, s.RawCommand())
			if cmd_prefix == "" {
				defaultShell := getDefaultShell()
				if s.RawCommand() == "" {
					if runtime.GOOS == "windows" {
						cmd = exec.Command(defaultShell)
					} else {
						cmd = exec.Command(defaultShell, "-l")
					}
				} else {
					if runtime.GOOS == "windows" {
						cmd = exec.Command(defaultShell, "/c", s.RawCommand())
					} else {
						cmd = exec.Command(defaultShell, "-c", s.RawCommand())
					}
				}
			}
			d, _ := os.UserHomeDir()
			cmd.Dir = d
			tcpR, okR := s.RemoteAddr().(*net.TCPAddr)
			tcpL, okL := s.LocalAddr().(*net.TCPAddr)
			rem_ip, rem_port, loc_ip, loc_port := "null", uint64(0), "null", 0
			if okR && okL {
				rem_ip, rem_port, loc_ip, loc_port = tcpR.IP.String(), uint64(tcpR.Port), tcpL.IP.String(), tcpL.Port
			} else {
				// for other type of listeners (e.g. unix sockets), use a unique value as remote port
				rem_port, _ = strconv.ParseUint(strings.TrimPrefix(fmt.Sprintf("%p", s), "0x"), 16, 64)
			}
			cmd.Env = append(os.Environ(),
				fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", rem_ip, rem_port, loc_ip, loc_port),
				fmt.Sprintf("SSH_CLIENT=%s %d %d", rem_ip, rem_port, loc_port)) //NOTE: SSH_CLIENT is deprecated
			for _, env := range s.Environ() {
				kv := strings.SplitN(env, "=", 2)
				if len(kv) != 2 {
					continue
				}
				key := kv[0]
				for _, pattern := range acceptEnv {
					if matched, _ := path.Match(pattern, key); matched { //use path.Match for Glob pattern matching
						cmd.Env = append(cmd.Env, env)
						break
					}
				}
			}
			if ssh.AgentRequested(s) {
				l, sockpath, err := NewAgentListener(perlPath)
				if err != nil {
					log.Fatal(err)
				}
				defer l.Close()
				go ssh.ForwardAgentConnections(l, nil, s)
				cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", sockpath))
			}
			ptyReq, winCh, isPty := s.Pty()
			var xPty xpty.Pty
			if isPty {
				var err error
				xPty, err = xpty.NewPty(ptyReq.Window.Width, ptyReq.Window.Height)
				if err != nil {
					panic(err)
				}
				defer xPty.Close()
				cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
				{
					ssh_tty := fmt.Sprintf("SSH_TTY=/xpty-dummy/%s-%d-%s-%d", tcpR.IP.String(), tcpR.Port, tcpL.IP.String(), tcpL.Port)
					if runtime.GOOS != "windows" {
						if ttyDevice, ok := xPty.(interface{ Name() string }); ok {
							ssh_tty = fmt.Sprintf("SSH_TTY=%s", ttyDevice.Name())
						}
					}
					cmd.Env = append(cmd.Env, ssh_tty)
				}
				setSysProcAttr(cmd, isPty)
				if err := xPty.Start(cmd); err != nil {
					s.Exit(1)
					return err
				}
				go func() {
					for win := range winCh {
						_ = xPty.Resize(win.Width, win.Height)
					}
				}()
				go io.Copy(xPty, s)
				go io.Copy(s, xPty)
			} else {
				stdin, _ := cmd.StdinPipe()
				cmd.Stdout, cmd.Stderr = s, s.Stderr()
				setSysProcAttr(cmd, isPty)
				err := cmd.Start()
				if err != nil {
					s.Exit(1)
					return err
				}
				go func() {
					defer stdin.Close()
					io.Copy(stdin, s)
				}()
			}
			waitDone := make(chan error, 1)
			go func() {
				waitDone <- cmd.Wait()
			}()

			select {
			case <-s.Context().Done():
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
			case err := <-waitDone:
				if isPty && xPty != nil {
					_ = xPty.Close()
				}
				if err != nil {
					if exiterr, ok := err.(*exec.ExitError); ok {
						if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
							s.Exit(status.ExitStatus())
							return nil
						}
					}
					s.Exit(1)
				} else {
					s.Exit(0)
				}
			}
			return nil
		},
		LocalPortForwardingCallback: func(ctx ssh.Context, _ gossh.ConnMetadata, dhost string, dport uint32) (bool, error) {
			return true, nil
		},
		ReversePortForwardingCallback: func(ctx ssh.Context, _ gossh.ConnMetadata, host string, port uint32) (bool, error) { return true, nil },
		LocalUnixForwardingCallback: func(ctx ssh.Context, _ gossh.ConnMetadata, socketPath string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
		ReverseUnixForwardingCallback: func(ctx ssh.Context, conn gossh.ConnMetadata, socketPath string) (net.Listener, error) {
			var listenConfig net.ListenConfig
			listener, err := listenConfig.Listen(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			unlinker, ok := listener.(interface{ SetUnlinkOnClose(bool) })
			if !ok {
				_ = listener.Close()
				return nil, errors.New("unix listener does not support unlink-on-close")
			}
			unlinker.SetUnlinkOnClose(true)
			if err := os.Chmod(socketPath, 0o600); err != nil {
				_ = listener.Close()
				return nil, err
			}
			return listener, nil
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":                          forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward":                   forwardHandler.HandleSSHRequest,
			"streamlocal-forward@openssh.com":        forwardedUnixHandler.HandleSSHRequest,
			"cancel-streamlocal-forward@openssh.com": forwardedUnixHandler.HandleSSHRequest,
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip":                   ssh.DirectTCPIPHandler,
			"session":                        ssh.DefaultSessionHandler,
			"direct-streamlocal@openssh.com": ssh.DirectStreamLocalHandler,
		},
	}
	for _, v := range options {
		server.SetOption(v)
	}
	if len(server.HostSigners) == 0 {
		log.Println("Warning: no hostkey set (possibly due to missing permission). Will generate random one.")
	}
	log.Println("starting ssh server...")
	return server.Serve(ctx, ln)
}

func getDefaultShell() string {
	if runtime.GOOS == "windows" {
		if comspec := os.Getenv("ComSpec"); comspec != "" {
			return comspec
		}
		if path, err := exec.LookPath("pwsh.exe"); err == nil {
			return path
		}
		return "powershell.exe"
	}
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}
	return "/bin/sh"
}

func SftpHandler(sess ssh.Session) error {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		return fmt.Errorf("initialize sftp server: %w", err)
	}
	serveErr := server.Serve()
	closeErr := server.Close()
	if errors.Is(serveErr, io.EOF) {
		serveErr = nil
		fmt.Println("sftp client exited session.")
	}
	return errors.Join(serveErr, closeErr)
}
