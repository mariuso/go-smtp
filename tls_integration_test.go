package smtp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTLSIntegrationFullScenario tests a complete TLS scenario end-to-end
func TestTLSIntegrationFullScenario(t *testing.T) {
	// Track all state transitions and logs
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "test: ", 0)
	
	var mu sync.Mutex
	var states []ConnState

	be := &tlsTestBackend{}
	s := NewServer(be)
	s.ErrorLog = logger
	s.TLSDebug = true
	s.TLSTimeout = 5 * time.Second
	s.ConnState = func(conn net.Conn, state ConnState) {
		mu.Lock()
		states = append(states, state)
		mu.Unlock()
	}
	
	// Use valid certificate
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	// Create client with proper TLS config
	testRootCAs := x509.NewCertPool()
	testRootCAs.AppendCertsFromPEM(localhostCert)
	clientTLSConfig := &tls.Config{
		RootCAs:    testRootCAs,
		ServerName: "example.com",
	}

	// Connect and perform full SMTP + TLS session
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	
	greeting := string(buf[:n])
	if !strings.Contains(greeting, "220") {
		t.Fatalf("Expected SMTP greeting, got: %s", greeting)
	}

	// Send EHLO
	conn.Write([]byte("EHLO test.example.com\r\n"))
	err = readEHLOResponse(conn)
	if err != nil {
		t.Fatal(err)
	}

	// Send STARTTLS
	conn.Write([]byte("STARTTLS\r\n"))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	
	response := string(buf[:n])
	if !strings.Contains(response, "220") {
		t.Fatalf("Expected TLS ready response, got: %s", response)
	}

	// Perform TLS handshake
	tlsConn := tls.Client(conn, clientTLSConfig)
	err = tlsConn.Handshake()
	if err != nil {
		t.Fatal("TLS handshake should succeed:", err)
	}

	// Continue with SMTP over TLS
	tlsConn.Write([]byte("EHLO test.example.com\r\n"))
	// Read multi-line EHLO response over TLS
	for {
		n, err = tlsConn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		response := string(buf[:n])
		if strings.Contains(response, "250 ") { // Final line
			break
		}
	}
	
	// Send QUIT to properly close
	tlsConn.Write([]byte("QUIT\r\n"))
	n, err = tlsConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	
	if !strings.Contains(string(buf[:n]), "221") {
		t.Errorf("Expected QUIT response, got: %s", string(buf[:n]))
	}

	// Give server time to process everything
	time.Sleep(200 * time.Millisecond)

	// Verify state transitions
	mu.Lock()
	statesCopy := make([]ConnState, len(states))
	copy(statesCopy, states)
	mu.Unlock()

	// Check for expected states
	expectedStates := map[ConnState]bool{
		StateNew:        false,
		StateActive:     false,
		StateStartTLS:   false,
		StateTLSSuccess: false,
		StateClosed:     false,
	}

	for _, state := range statesCopy {
		if _, exists := expectedStates[state]; exists {
			expectedStates[state] = true
		}
	}

	for state, found := range expectedStates {
		if !found {
			t.Errorf("Expected state %v not found in transitions: %v", state, statesCopy)
		}
	}

	// Verify debug logging
	logs := logBuf.String()
	
	if !strings.Contains(logs, "TLS established") {
		t.Errorf("Expected TLS establishment log, got: %s", logs)
	}
	
	if !strings.Contains(logs, "server_name=") {
		t.Errorf("Expected detailed TLS debug info, got: %s", logs)
	}
}

// TestTLSWithDifferentCipherSuites tests TLS with various cipher configurations
func TestTLSWithDifferentCipherSuites(t *testing.T) {
	cipherSuites := []struct {
		name   string
		suites []uint16
	}{
		{
			name:   "Default cipher suites",
			suites: nil, // Use defaults
		},
		{
			name: "Strong cipher suites only",
			suites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
			},
		},
	}

	for _, tc := range cipherSuites {
		t.Run(tc.name, func(t *testing.T) {
			be := &tlsTestBackend{}
			s := NewServer(be)
			
			// Use valid certificate
			keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
			if err != nil {
				t.Fatal(err)
			}
			s.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{keypair},
				CipherSuites: tc.suites,
			}
			defer s.Close()

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()

			go s.Serve(l)

			// Create client with matching TLS config
			testRootCAs := x509.NewCertPool()
			testRootCAs.AppendCertsFromPEM(localhostCert)
			clientTLSConfig := &tls.Config{
				RootCAs:      testRootCAs,
				ServerName:   "example.com",
				CipherSuites: tc.suites,
			}

			// Test connection
			conn, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			// Quick TLS handshake test
			buf := make([]byte, 1024)
			conn.Read(buf) // greeting

			conn.Write([]byte("EHLO test.example.com\r\n"))
			readEHLOResponse(conn)

			conn.Write([]byte("STARTTLS\r\n"))
			conn.Read(buf) // TLS ready

			tlsConn := tls.Client(conn, clientTLSConfig)
			err = tlsConn.Handshake()
			if err != nil {
				t.Fatalf("TLS handshake failed for %s: %v", tc.name, err)
			}

			// Verify connection state
			state := tlsConn.ConnectionState()
			if !state.HandshakeComplete {
				t.Errorf("Expected completed handshake for %s", tc.name)
			}
		})
	}
}

// TestTLSCertificateValidation tests various certificate scenarios
func TestTLSCertificateValidation(t *testing.T) {
	tests := []struct {
		name           string
		serverCert     func() tls.Certificate
		clientConfig   func() *tls.Config
		expectFailure  bool
	}{
		{
			name: "Valid certificate",
			serverCert: func() tls.Certificate {
				cert, _ := tls.X509KeyPair(localhostCert, localhostKey)
				return cert
			},
			clientConfig: func() *tls.Config {
				testRootCAs := x509.NewCertPool()
				testRootCAs.AppendCertsFromPEM(localhostCert)
				return &tls.Config{
					RootCAs:    testRootCAs,
					ServerName: "example.com",
				}
			},
			expectFailure: false,
		},
		{
			name: "Self-signed certificate with skip verify",
			serverCert: func() tls.Certificate {
				cert, _ := generateSelfSignedCert()
				return cert
			},
			clientConfig: func() *tls.Config {
				return &tls.Config{
					InsecureSkipVerify: true,
				}
			},
			expectFailure: false,
		},
		{
			name: "Self-signed certificate without skip verify",
			serverCert: func() tls.Certificate {
				cert, _ := generateSelfSignedCert()
				return cert
			},
			clientConfig: func() *tls.Config {
				return &tls.Config{
					ServerName: "test.example.com",
				}
			},
			expectFailure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &tlsTestBackend{}
			s := NewServer(be)
			s.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{tt.serverCert()},
			}
			defer s.Close()

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()

			go s.Serve(l)

			// Test connection
			conn, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			conn.Read(buf) // greeting

			conn.Write([]byte("EHLO test.example.com\r\n"))
			readEHLOResponse(conn)

			conn.Write([]byte("STARTTLS\r\n"))
			conn.Read(buf) // TLS ready

			tlsConn := tls.Client(conn, tt.clientConfig())
			err = tlsConn.Handshake()

			if tt.expectFailure && err == nil {
				t.Errorf("Expected TLS handshake to fail for %s", tt.name)
			} else if !tt.expectFailure && err != nil {
				t.Errorf("Expected TLS handshake to succeed for %s, got: %v", tt.name, err)
			}
		})
	}
}

// TestTLSConcurrentConnections tests multiple concurrent TLS connections
func TestTLSConcurrentConnections(t *testing.T) {
	const numConnections = 10

	be := &tlsTestBackend{}
	s := NewServer(be)
	
	// Use valid certificate
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	// Create client TLS config
	testRootCAs := x509.NewCertPool()
	testRootCAs.AppendCertsFromPEM(localhostCert)
	clientTLSConfig := &tls.Config{
		RootCAs:    testRootCAs,
		ServerName: "example.com",
	}

	// Launch concurrent connections
	var wg sync.WaitGroup
	errors := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			conn.Read(buf) // greeting

			conn.Write([]byte("EHLO test.example.com\r\n"))
			err = readEHLOResponse(conn)
			if err != nil {
				errors <- err
				return
			}

			conn.Write([]byte("STARTTLS\r\n"))
			conn.Read(buf) // TLS ready

			tlsConn := tls.Client(conn, clientTLSConfig)
			err = tlsConn.Handshake()
			if err != nil {
				errors <- err
				return
			}

			// Send a command over TLS
			tlsConn.Write([]byte("QUIT\r\n"))
			tlsConn.Read(buf)
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent connection error: %v", err)
	}
}

// generateSelfSignedCert generates a self-signed certificate for testing
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost", "test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}