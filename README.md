# single-user-sshd (susshd)
Supported:
- *nix, Windows >=10 (required by ConPTY)
- port forwarding, including UNIX socket
- ssh agent forwarding
  - for Windows, native ssh-agent (named pipe) and Cygwin-style UNIX socket (requires `-perl`). UNIX sockets are placed in %TEMP%\susshd, named accordingly with the named pipe behind it.
- sftp
  - `-sftp-server` makes the binary act as a standalone sftp-server on stdin/stdout
- public key authentication (no password auth)
  - keys are read from authorized_keys files (`-a`, repeatable) on each authentication attempt
  - supported options: `command="..."` (`internal-sftp` runs the built-in sftp server), `restrict`, `[no-]port-forwarding`, `[no-]agent-forwarding`, `[no-]pty`, `internal-sftp@susshd` (susshd extension: sftp subsystem requests are served by the built-in sftp server even if `command` is set; note that sftp access is then not restricted by the command). `[no-]X11-forwarding` and `[no-]user-rc` are accepted and have no effect. Keys with other options are ignored.
- environment variable forwarding via SendEnv/SetEnv (with AcceptEnv-style filtering)
- some environment variables (SSH_CONNECTION, SSH_CLIENT, SSH_TTY)

# replace ssh library
This library uses https://github.com/ge9-2/go-ssh-unix-socket, a customized version of [gliderlabs/ssh](https://github.com/gliderlabs/ssh).
To use susshd as library, run this beforehand:
```
go mod edit -replace github.com/gliderlabs/ssh=github.com/ge9-2/go-ssh-unix-socket@master
go mod tidy
```

# Use cases
## non-root setup
`susshd` provides a quite simple way to serve SSH server for non-root users. Some popular SSH servers can be used by non-root users, but its configuration is a bit trickier.
## use in Windows
`susshd` supports ssh-agent forwarding, unlike the official OpenSSH server. It is also useful to expose GUI session. When used with VS Code Remote SSH, the executable **must** be renamed as `sshd.exe`. 