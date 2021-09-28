package drivers

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"golang.org/x/crypto/ssh"
)

var ()

type sshd struct {
	globutil *gctx.GlobalUtils
	config   ssh.ServerConfig
}

func init() {
	s := &sshd{}
	s.config = ssh.ServerConfig{
		MaxAuthTries:      -1,
		ServerVersion:     "SSH-2.0-libssh-0.6.0",
		PasswordCallback:  s.passwordCallback,
		PublicKeyCallback: s.keyCallback,
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatal(err)
	}
	s.config.AddHostKey(hostKey)

	AddDriver(s)
}

func (s *sshd) Patterns() [][]byte {
	return [][]byte{
		[]byte("SSH-2.0"),
	}
}

func (s *sshd) ServeTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if mux, ok := c.(*muxconn.MuxConn); ok {
			s.globutil = gctx.GetGlobalFromContext(mux.Context, "sshd")
		}
		go func(c net.Conn) {
			sc, _, _, err := ssh.NewServerConn(c, &s.config)
			if err != nil {
				s.globutil.Logger.Debug().Err(err).Msg("failed handshake")
				return
			}

			sc.Close()
		}(c)
	}
}

func (s *sshd) keyCallback(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	s.globutil.NewSession(1, "").
		ATTACKEntBruteForce(
			gctx.Value{Key: "user", Value: c.User()},
			gctx.Value{Key: "pubkey", Value: string(pubKey.Marshal())},
			gctx.Value{Key: "pubkeytype", Value: pubKey.Type()},
		)
	return nil, fmt.Errorf("unknown public key for %q", c.User())
}

func (s *sshd) passwordCallback(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	s.globutil.NewSession(1, "").
		ATTACKEntPasswordGuessing(
			gctx.Value{Key: "user", Value: c.User()},
			gctx.Value{Key: "pass", Value: string(pass)},
		)

	return nil, fmt.Errorf("password rejected for %q", c.User())
}
