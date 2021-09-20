package conman

import (
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

	"github.com/antihax/gambit/internal/muxconn"
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
		SerialNumber: big.NewInt(fake.Int64()),
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

// unwrapTLS attempts to return a TLS decrypting TCP MuxConn
func (s *ConnectionManager) unwrapTLS(conn net.Conn) (*muxconn.MuxConn, []byte, int, error) {
	n := 1500
	buf := make([]byte, n)
	tlsConn := tls.Server(conn, &s.tlsConfig)
	muc := muxconn.NewMuxConn(s.RootContext, tlsConn)
	r := muc.StartSniffing()
	n, err := r.Read(buf)
	if err != nil {
		if err != io.EOF {
			s.logger.Debug().Str("network", "tcp").
				Err(err).Msg("error unwrapping tls")
			muc.Reset()
			return nil, nil, 0, err
		}
	}

	return muc, buf, n, err
}

// unwrapTLS attempts to return a DTLS decrypting UDP MuxConn
func (s *ConnectionManager) unwrapDTLS(conn net.Conn) (*muxconn.MuxConn, []byte, int, error) {
	n := 1500
	buf := make([]byte, n)
	tlsConn, err := dtls.Server(conn, &s.dtlsConfig)
	if err != nil {
		if err != io.EOF {
			s.logger.Debug().Str("network", "udp").
				Err(err).Msg("error unwrapping dtls")
			return nil, nil, 0, err
		}
	}
	muc := muxconn.NewMuxConn(s.RootContext, tlsConn)
	r := muc.StartSniffing()
	n, err = r.Read(buf)
	if err != nil {
		if err != io.EOF {
			s.logger.Debug().Str("network", "udp").
				Err(err).Msg("error unwrapping dtls")
			muc.Reset()
			return nil, nil, 0, err
		}
	}

	return muc, buf, n, err
}
