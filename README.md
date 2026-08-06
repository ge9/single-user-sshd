# single-user-sshd (susshd)
Supported:
- *nix, Windows >=10 (required by ConPTY)
- Port forwarding, including UNIX socket
- ssh agent forwarding (uses Windows native ssh agent)
- sftp
- Public key authentication (no password auth)

## replace ssh library for Unix socket support
To use susshd as library, run this beforehand:
```
go mod edit -replace github.com/gliderlabs/ssh=github.com/ge9-2/go-ssh-unix-socket@master
go mod tidy
```
