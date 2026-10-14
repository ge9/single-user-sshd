package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/engity-com/ssh-server-go"
	susshd "github.com/ge9/single-user-sshd"
)

type multi []string

func (m *multi) String() string     { return "" }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	//:22 is default for gliderlabs/ssh
	bind := flag.String("b", ":22", "bind address:port or unix socket")
	perlPath := flag.String("perl", "", "if specified, used to provide Cygwin style UNIX socket (effective only in Windows)")
	acceptEnv := flag.String("accept-env", "LANG,LC_*", "comma-separated list of accepted envs")
	var authKeyFiles multi
	flag.Var(&authKeyFiles, "a", "authorized_keys file path (repeatable)")
	var hostkeys multi
	flag.Var(&hostkeys, "h", "host key file path (repeatable)")
	sftpServer := flag.Bool("sftp-server", false, "serve SFTP on stdin/stdout like sftp-server and exit")
	flag.Parse()
	if *sftpServer {
		if err := susshd.ServeSftp(struct {
			io.Reader
			io.WriteCloser
		}{os.Stdin, os.Stdout}); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(hostkeys) == 0 || len(authKeyFiles) == 0 {
		log.Fatal("host key or authorized_keys file is missing")
	}
	var opts []ssh.Option
	for _, h := range hostkeys {
		opts = append(opts, ssh.HostKeyFile(h))
	}
	nKeys := 0
	for _, f := range authKeyFiles {
		keys, err := susshd.LoadAuthorizedKeys(f)
		if err != nil {
			log.Fatal(err)
		}
		nKeys += len(keys)
	}
	if nKeys == 0 {
		log.Println("Warning: no valid authorized key found")
	}
	opts = append(opts, susshd.AuthorizedKeysAuth(authKeyFiles))
	ln, err := createListener(*bind)
	if err != nil {
		log.Fatal(err)
	}
	err = susshd.BaseSSH(context.Background(), ln, strings.Split(*acceptEnv, ","), *perlPath, opts...)
	if err != nil {
		log.Printf("server error: %v", err)
	}
	ln.Close()
}

func createListener(addr string) (net.Listener, error) {
	if addr == "" {
		addr = ":22"
	}
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		os.Remove(addr)
		return net.Listen("unix", addr)
	}
	return net.Listen("tcp", addr)
}
