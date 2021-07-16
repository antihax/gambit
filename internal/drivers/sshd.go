package drivers

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net"

	"github.com/antihax/pass/pkg/muxconn"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

var (
	config ssh.ServerConfig
)

type sshd struct {
	logger zerolog.Logger
}

func (s *sshd) ServeTCP(ln net.Listener) error {
	if mux, ok := ln.(muxconn.MuxListener); ok {
		s.logger = mux.Logger.With().Str("driver", "sshd").Logger()
	} else {
		log.Fatalln("cannot obtain logger")
	}
	for {
		nConn, err := ln.Accept()
		if err != nil {
			s.logger.Debug().Err(err).Msg("failed accept")
		}
		_, _, _, err = ssh.NewServerConn(nConn, &config)
		if err != nil {
			s.logger.Debug().Err(err).Msg("failed handshake")
			continue
		}
	}
}

func (s *sshd) keyCallback(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	s.logger.Warn().Str("user", c.User()).Str("pubkey", string(pubKey.Marshal())).Str("pubkeytype", pubKey.Type()).Msg("tried public key")
	return nil, fmt.Errorf("unknown public key for %q", c.User())
}

func (s *sshd) passwordCallback(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	s.logger.Warn().Str("user", c.User()).Str("password", string(pass)).Msg("tried password")
	return nil, fmt.Errorf("password rejected for %q", c.User())
}

func init() {
	s := &sshd{}
	config = ssh.ServerConfig{
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
	config.AddHostKey(hostKey)

	AddDriver([]byte("SSH-2.0"), s)
}