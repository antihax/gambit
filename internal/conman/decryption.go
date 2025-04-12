package conman

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/pkg/muxconn"
	fake "github.com/brianvoe/gofakeit/v6"
	"github.com/pion/dtls/v2"
)

// fakeTLSCertificate creates a fake TLS cert for decrypting TLS
func (s *ConnectionManager) fakeTLSCertificate() (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tml := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(25, 0, 0),
		SerialNumber: big.NewInt(int64(fake.Uint32())),
		Subject: pkix.Name{
			CommonName:   fake.DomainName(),
			Organization: []string{fake.Company()},
		},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

func (s *ConnectionManager) getGlobalContext() (context.Context, *gctx.GlobalUtils) {
	g := &gctx.GlobalUtils{
		Store:  s.storeChan,
		Logger: s.logger,
	}
	return gctx.NewGlobalContext(context.Background(), g), g
}

// decryptConn attempts to return a decrypting connection
func (s *ConnectionManager) decryptConn(ctx context.Context, conn net.Conn, network string) (*muxconn.MuxConn, []byte, int, error) {
	var (
		decryptConn net.Conn
		err         error
	)

	if network == "tcp" {
		decryptConn = tls.Server(conn, &s.tlsConfig)
	} else {
		decryptConn, err = dtls.Server(conn, &s.dtlsConfig)
		if err != nil {
			s.logger.Trace().Str("network", network).Err(err).Msg("error decrypting session")
			return nil, nil, 0, err
		}
	}

	// Setup context
	muc, err := muxconn.NewMuxConn(ctx, decryptConn)
	if err != nil {
		s.logger.Debug().Str("network", network).Err(err).Msg("error building NewMuxConn")
		return nil, nil, 0, err
	}

	// Reset and start sniffing
	r := muc.StartSniffing()
	bufSize := 4096
	if network == "udp" {
		bufSize = 1500
	}
	buf := make([]byte, bufSize)

	n, err := r.Read(buf)
	if err != nil {
		if err != io.EOF {
			s.logger.Debug().Str("network", network).Err(err).Msg("error unwrapping tls")
			muc.Reset()
			return nil, nil, 0, err
		}
	}

	return muc, buf, n, err
}
