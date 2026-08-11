package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"

	susshd "github.com/ge9/single-user-sshd"
	"github.com/gliderlabs/ssh"
)

type multi []string

func (m *multi) String() string     { return "" }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	//:22 is default for gliderlabs/ssh
	bind := flag.String("b", ":22", "bind address:port or unix socket")
	perlPath := flag.String("perl", "", "if specified, used to provide Cygwin style UNIX socket (effective only in Windows)")
	acceptEnv := flag.String("accept-env", "LANG,LC_*", "comma-separated list of accepted envs")
	cmd := flag.String("c", "", "command prefix (optional)")
	var pubkeys multi
	flag.Var(&pubkeys, "p", "authorized public key string (repeatable)")
	var hostkeys multi
	flag.Var(&hostkeys, "h", "host key file path (repeatable)")
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
	ln, err := createListener(*bind)
	if err != nil {
		log.Fatal(err)
	}
	err = susshd.BaseSSH(ln, *cmd, strings.Split(*acceptEnv, ","), *perlPath, opts...)
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
