package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProbeTLSCertificateStrictVerification(t *testing.T) {
	t.Run("trusted certificate succeeds", func(t *testing.T) {
		caCert, caKey := newTestCA(t)
		serverCert, leaf := newTestServerCertificate(t, caCert, caKey, []string{"127.0.0.1"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(caCert)

		port, closeServer := startTestTLSServer(t, serverCert)
		defer closeServer()

		observed, err := probeTLSCertificateWithRootCAs(context.Background(), "127.0.0.1", port, rootCAs)
		if err != nil {
			t.Fatalf("probeTLSCertificateWithRootCAs() error = %v", err)
		}
		if observed.Fingerprint != certificateFingerprint(leaf) {
			t.Fatalf("Fingerprint = %q, want %q", observed.Fingerprint, certificateFingerprint(leaf))
		}
		if observed.Serial != leaf.SerialNumber.String() {
			t.Fatalf("Serial = %q, want %q", observed.Serial, leaf.SerialNumber.String())
		}
		if !observed.NotAfter.Equal(leaf.NotAfter) {
			t.Fatalf("NotAfter = %s, want %s", observed.NotAfter, leaf.NotAfter)
		}
	})

	t.Run("untrusted certificate reports authority error", func(t *testing.T) {
		caCert, caKey := newTestCA(t)
		serverCert, _ := newTestServerCertificate(t, caCert, caKey, []string{"127.0.0.1"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

		port, closeServer := startTestTLSServer(t, serverCert)
		defer closeServer()

		_, err := probeTLSCertificateWithRootCAs(context.Background(), "127.0.0.1", port, nil)
		if err == nil {
			t.Fatal("probeTLSCertificateWithRootCAs() expected error")
		}
		if !strings.Contains(err.Error(), "net::ERR_CERT_AUTHORITY_INVALID") {
			t.Fatalf("error = %q, want authority error code", err)
		}
	})

	t.Run("hostname mismatch reports common name error", func(t *testing.T) {
		caCert, caKey := newTestCA(t)
		serverCert, _ := newTestServerCertificate(t, caCert, caKey, []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(caCert)

		port, closeServer := startTestTLSServer(t, serverCert)
		defer closeServer()

		_, err := probeTLSCertificateWithRootCAs(context.Background(), "127.0.0.1", port, rootCAs)
		if err == nil {
			t.Fatal("probeTLSCertificateWithRootCAs() expected error")
		}
		if !strings.Contains(err.Error(), "net::ERR_CERT_COMMON_NAME_INVALID") {
			t.Fatalf("error = %q, want common name error code", err)
		}
	})

	t.Run("expired certificate reports date error", func(t *testing.T) {
		caCert, caKey := newTestCA(t)
		serverCert, _ := newTestServerCertificate(t, caCert, caKey, []string{"127.0.0.1"}, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(caCert)

		port, closeServer := startTestTLSServer(t, serverCert)
		defer closeServer()

		_, err := probeTLSCertificateWithRootCAs(context.Background(), "127.0.0.1", port, rootCAs)
		if err == nil {
			t.Fatal("probeTLSCertificateWithRootCAs() expected error")
		}
		if !strings.Contains(err.Error(), "net::ERR_CERT_DATE_INVALID") {
			t.Fatalf("error = %q, want date error code", err)
		}
	})
}

func startTestTLSServer(t *testing.T, cert tls.Certificate) (int, func()) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q) error = %v", portStr, err)
	}

	return port, func() {
		_ = listener.Close()
		<-done
	}
}

func newTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate(ca) error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(ca) error = %v", err)
	}

	return cert, key
}

func newTestServerCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, hosts []string, notBefore, notAfter time.Time) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(server) error = %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(server) error = %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, leaf
}
