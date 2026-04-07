package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
)

type multi []string

func (m *multi) String() string     { return "" }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	//:22 is default for gliderlabs/ssh
	bind := flag.String("b", ":22", "bind address:port or unix socket")
	cmd := flag.String("c", "", "command prefix (optional)")
	var pubkeys multi
	flag.Var(&pubkeys, "k", "authorized public key (repeatable)")
	var hostkeys multi
	flag.Var(&hostkeys, "h", "host key file (repeatable)")
	flag.Parse()
	if len(hostkeys) == 0 || len(pubkeys) == 0 {
		log.Fatal("host key or pubkey is missing")
	}
	var opts []ssh.Option
	for _, h := range hostkeys {
		opts = append(opts, ssh.HostKeyFile(h))
	}
	var authorizedKeys []ssh.PublicKey
	for _, kStr := range pubkeys {
		pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(kStr))
		authorizedKeys = append(authorizedKeys, pub)
	}
	opts = append(opts, ssh.PublicKeyAuth(
		func(ctx ssh.Context, k ssh.PublicKey) bool {
			for _, authKey := range authorizedKeys {
				if ssh.KeysEqual(k, authKey) {
					return true
				}
			}
			return false
		}))

	BaseSSH(*bind, *cmd, opts...)
}

// Unix forwarding is currently not merged into master: https://github.com/gliderlabs/ssh/pull/196
func BaseSSH(addr, cmd_prefix string, options ...ssh.Option) {
	forwardHandler := &ssh.ForwardedTCPHandler{}
	// Uncomment this to enable remote unix forwarding
	// forwardedUnixHandler := &ssh.ForwardedUnixHandler{}
	server := ssh.Server{
		Addr:              addr,
		SubsystemHandlers: map[string]ssh.SubsystemHandler{"sftp": SftpHandler},
		Handler: func(s ssh.Session) {
			cmd := exec.Command(cmd_prefix, s.RawCommand())
			if cmd_prefix == "" {
				defaultShell := os.Getenv("SHELL")
				if defaultShell == "" {
					defaultShell = "/bin/sh"
				}
				cmd = exec.Command(defaultShell, "-c", s.RawCommand())
				if s.RawCommand() == "" {
					cmd = exec.Command(defaultShell, "-l")
				}
			}
			d, _ := os.UserHomeDir()
			cmd.Dir = d
			tcpR, tcpL := s.RemoteAddr().(*net.TCPAddr), s.LocalAddr().(*net.TCPAddr)
			cmd.Env = append(os.Environ(),
				fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", tcpR.IP.String(), tcpR.Port, tcpL.IP.String(), tcpL.Port),
				fmt.Sprintf("SSH_CLIENT=%s %d %d", tcpR.IP.String(), tcpR.Port, tcpL.Port)) //NOTE: SSH_CLIENT is deprecated
			if ssh.AgentRequested(s) {
				l, err := ssh.NewAgentListener()
				if err != nil {
					log.Fatal(err)
				}
				defer l.Close()
				go ssh.ForwardAgentConnections(l, s)
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", "SSH_AUTH_SOCK", l.Addr().String()))
			}
			ptyReq, winCh, isPty := s.Pty()
			var f *os.File
			if isPty {
				var slink *os.File
				var err error
				f, slink, err = pty.Open()
				if err != nil {
					panic(err)
				}
				defer f.Close()
				cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
				cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_TTY=%s", slink.Name()))
				cmd.Stdin, cmd.Stdout, cmd.Stderr = slink, slink, slink
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}

				if err := cmd.Start(); err != nil {
					s.Exit(1)
					return
				}
				slink.Close()
				go func() {
					for win := range winCh {
						pty.Setsize(f, &pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)})
					}
				}()
				go io.Copy(f, s) //stdin
				go io.Copy(s, f) //stdout
			} else {
				stdin, _ := cmd.StdinPipe()
				cmd.Stdout, cmd.Stderr = s, s.Stderr()
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
				err := cmd.Start()
				if err != nil {
					s.Exit(1)
					return
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
					syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				}
			case err := <-waitDone:
				if isPty && f != nil {
					f.Close()
				}
				if err != nil {
					if exiterr, ok := err.(*exec.ExitError); ok {
						if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
							s.Exit(status.ExitStatus())
							return
						}
					}
					s.Exit(1)
				} else {
					s.Exit(0)
				}
			}
		},
		LocalPortForwardingCallback:   ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool { return true }),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool { return true }),
		// Uncomment this to enable local unix forwarding
		// LocalUnixForwardingCallback:   ssh.SimpleUnixLocalForwardingCallback,
		// Uncomment this to enable remote unix forwarding
		// ReverseUnixForwardingCallback: ssh.SimpleUnixReverseForwardingCallback,
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
			// Uncomment this to enable remote unix forwarding
			// "streamlocal-forward@openssh.com":        forwardedUnixHandler.HandleSSHRequest,
			// "cancel-streamlocal-forward@openssh.com": forwardedUnixHandler.HandleSSHRequest,
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
			"session":      ssh.DefaultSessionHandler,
			// Uncomment this to enable local unix forwarding
			// "direct-streamlocal@openssh.com": ssh.DirectStreamLocalHandler,
		},
	}
	for _, v := range options {
		server.SetOption(v)
	}
	log.Println("starting ssh server...")
	if server.Addr == "" {
		server.Addr = ":22"
	}
	_, _, err := net.SplitHostPort(server.Addr)
	var ln net.Listener
	if err != nil {
		os.Remove(server.Addr)
		ln, err = net.Listen("unix", server.Addr)
	} else {
		ln, err = net.Listen("tcp", server.Addr)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	log.Fatal(server.Serve(ln))
}

func SftpHandler(sess ssh.Session) {
	d, _ := os.UserHomeDir()
	serverOptions := []sftp.ServerOption{
		sftp.WithServerWorkingDirectory(d),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		fmt.Println("sftp client exited session.")
	} else if err != nil {
		fmt.Println("sftp server completed with error:", err)
	}
}
