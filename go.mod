module github.com/ge9/single-user-sshd

go 1.25.0

require github.com/gliderlabs/ssh v0.3.8

require (
	github.com/charmbracelet/x/conpty v0.2.0 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/xpty v0.1.4 // direct
	github.com/kr/fs v0.1.0 // indirect
)

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/pkg/sftp v1.13.10
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/gliderlabs/ssh => github.com/ge9-2/go-ssh-unix-socket v0.3.9-0.20260806080818-fe6356dba37d
