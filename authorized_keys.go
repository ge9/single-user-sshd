package susshd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"
)

// KeyOptions holds the supported authorized_keys options of a key.
type KeyOptions struct {
	HasCommand        bool
	Command           string
	NoPortForwarding  bool
	NoAgentForwarding bool
	NoPty             bool
}

type keyOptionsKey struct{}

type AuthorizedKey struct {
	Key     ssh.PublicKey
	Options *KeyOptions
}

// keyOptionsOf returns the options stored by AuthorizedKeysAuth, or no restrictions if absent.
func keyOptionsOf(p *gossh.Permissions) *KeyOptions {
	if p != nil {
		if o, ok := p.ExtraData[keyOptionsKey{}].(*KeyOptions); ok {
			return o
		}
	}
	return &KeyOptions{}
}

// ParseKeyOptions parses options in the same way as OpenSSH. Later options override earlier ones.
func ParseKeyOptions(options []string) (*KeyOptions, error) {
	o := &KeyOptions{}
	for _, opt := range options {
		name, value, hasValue := strings.Cut(opt, "=")
		name = strings.ToLower(name)
		if name == "command" {
			if !hasValue {
				return nil, errors.New("command requires a value")
			}
			if o.HasCommand {
				return nil, errors.New("multiple command options")
			}
			cmd, err := dequote(value)
			if err != nil {
				return nil, fmt.Errorf("command: %w", err)
			}
			o.HasCommand, o.Command = true, cmd
			continue
		}
		if hasValue {
			return nil, fmt.Errorf("unsupported option %q", name)
		}
		switch name {
		case "restrict":
			o.NoPortForwarding, o.NoAgentForwarding, o.NoPty = true, true, true
		case "no-port-forwarding", "port-forwarding":
			o.NoPortForwarding = name == "no-port-forwarding"
		case "no-agent-forwarding", "agent-forwarding":
			o.NoAgentForwarding = name == "no-agent-forwarding"
		case "no-pty", "pty":
			o.NoPty = name == "no-pty"
		case "no-x11-forwarding", "x11-forwarding", "no-user-rc", "user-rc":
			// X11 forwarding and user rc are not supported anyway
		default:
			return nil, fmt.Errorf("unsupported option %q", name)
		}
	}
	return o, nil
}

// dequote removes surrounding double quotes and unescapes \" like OpenSSH.
func dequote(v string) (string, error) {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", errors.New("value must be double-quoted")
	}
	v = v[1 : len(v)-1]
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) && v[i+1] == '"' {
			i++
		} else if v[i] == '"' {
			return "", errors.New("unexpected double quote")
		}
		b.WriteByte(v[i])
	}
	return b.String(), nil
}

// LoadAuthorizedKeys reads an authorized_keys file. Lines with invalid or unsupported options are skipped.
func LoadAuthorizedKeys(path string) ([]AuthorizedKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []AuthorizedKey
	for len(data) > 0 {
		pub, _, options, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		data = rest
		opts, err := ParseKeyOptions(options)
		if err != nil {
			log.Printf("%s: ignoring key %s: %v", path, gossh.FingerprintSHA256(pub), err)
			continue
		}
		keys = append(keys, AuthorizedKey{pub, opts})
	}
	return keys, nil
}

// AuthorizedKeysAuth authenticates with keys in the files, which are read on each attempt.
// The first matching key wins.
func AuthorizedKeysAuth(files []string) ssh.Option {
	return ssh.PublicKeyAuth(func(ctx ssh.Context, _ gossh.ConnMetadata, k ssh.PublicKey) (bool, error) {
		for _, f := range files {
			keys, err := LoadAuthorizedKeys(f)
			if err != nil {
				log.Printf("failed to read authorized keys: %v", err)
				continue
			}
			for _, ak := range keys {
				if ssh.KeysEqual(k, ak.Key) {
					p := ctx.Permissions()
					if p.ExtraData == nil {
						p.ExtraData = map[any]any{}
					}
					p.ExtraData[keyOptionsKey{}] = ak.Options
					return true, nil
				}
			}
		}
		return false, nil
	})
}
