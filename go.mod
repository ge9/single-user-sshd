module github.com/ge9/single-user-sshd

go 1.27.0

require (
	github.com/Microsoft/go-winio v0.6.4
	github.com/charmbracelet/x/xpty v0.1.4 // direct
	github.com/engity-com/ssh-server-go v0.5.0
	github.com/gliderlabs/ssh v0.3.8
	github.com/pkg/sftp v1.13.12
	golang.org/x/crypto v0.59.0
)

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/charmbracelet/x/conpty v0.2.0 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/echocat/slf4g v1.9.1 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/pires/go-proxyproto v0.16.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace github.com/gliderlabs/ssh => github.com/ge9-2/go-ssh-unix-socket v0.3.9-0.20260806080818-fe6356dba37d
