# single-user-sshd (susshd)

# # replace ssh library for Unix socket support
To use susshd as library, run this beforehand:
```
go mod edit -replace github.com/gliderlabs/ssh=github.com/ge9-2/go-ssh-unix-socket@master
go mod tidy
```
