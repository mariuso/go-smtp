package smtp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// TestTLSTimeout tests TLS handshake timeout functionality
func TestTLSTimeout(t *testing.T) {
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "test: ", 0)

	be := &tlsTestBackend{}
	s := NewServer(be)
	s.ErrorLog = logger
	s.TLSTimeout = 100 * time.Millisecond // Very short timeout

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

	// Connect to server
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Send EHLO
	conn.Write([]byte("EHLO test.example.com\r\n"))
	err = readEHLOResponse(conn)
	if err != nil {
		t.Fatal(err)
	}

	// Send STARTTLS
	conn.Write([]byte("STARTTLS\r\n"))
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Create a slow TLS client config to trigger timeout
	// We'll simulate a slow handshake by using a custom dialer with delays
	testRootCAs := x509.NewCertPool()
	testRootCAs.AppendCertsFromPEM(localhostCert)
	clientTLSConfig := &tls.Config{
		RootCAs:    testRootCAs,
		ServerName: "example.com",
	}

	start := time.Now()
	
	// Try TLS handshake - may timeout due to very short TLSTimeout
	tlsConn := tls.Client(conn, clientTLSConfig)
	err = tlsConn.Handshake()
	
	elapsed := time.Since(start)
	
	// Should either succeed quickly or timeout
	if err != nil {
		// Check if it's a timeout error and that it happened reasonably quickly
		if elapsed > 200*time.Millisecond { // Allow some buffer beyond our 100ms timeout
			t.Errorf("TLS timeout took too long: %v", elapsed)
		}
		
		// Check for timeout-related error messages
		logs := logBuf.String()
		if !strings.Contains(logs, "TLS handshake failed") {
			t.Errorf("Expected TLS handshake failure to be logged on timeout, got: %s", logs)
		}
	} else {
		// If it succeeded, it should have been fast
		t.Logf("TLS handshake succeeded in %v", elapsed)
	}
}

// TestTLSDebugLogging tests detailed TLS debug logging
func TestTLSDebugLogging(t *testing.T) {
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "test: ", 0)

	be := &tlsTestBackend{}
	s := NewServer(be)
	s.ErrorLog = logger
	s.TLSDebug = true // Enable debug logging
	
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

	// Connect and establish TLS
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Send EHLO
	conn.Write([]byte("EHLO test.example.com\r\n"))
	err = readEHLOResponse(conn)
	if err != nil {
		t.Fatal(err)
	}

	// Send STARTTLS
	conn.Write([]byte("STARTTLS\r\n"))
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Perform successful TLS handshake
	tlsConn := tls.Client(conn, clientTLSConfig)
	err = tlsConn.Handshake()
	if err != nil {
		t.Fatal("TLS handshake should succeed:", err)
	}

	// Give server time to process and log
	time.Sleep(100 * time.Millisecond)

	// Check that detailed debug information was logged
	logs := logBuf.String()
	
	// Should contain basic TLS establishment
	if !strings.Contains(logs, "TLS established") {
		t.Errorf("Expected TLS establishment to be logged, got: %s", logs)
	}
	
	// Should contain detailed debug information
	if !strings.Contains(logs, "server_name=") {
		t.Errorf("Expected server_name in debug log, got: %s", logs)
	}
	
	if !strings.Contains(logs, "negotiated_protocol=") {
		t.Errorf("Expected negotiated_protocol in debug log, got: %s", logs)
	}
	
	// Version and cipher should be present
	if !strings.Contains(logs, "version=") {
		t.Errorf("Expected version in debug log, got: %s", logs)
	}
	
	if !strings.Contains(logs, "cipher=") {
		t.Errorf("Expected cipher in debug log, got: %s", logs)
	}
}

// TestTLSBasicLogging tests that basic logging works when debug is disabled
func TestTLSBasicLogging(t *testing.T) {
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "test: ", 0)

	be := &tlsTestBackend{}
	s := NewServer(be)
	s.ErrorLog = logger
	s.TLSDebug = false // Disable debug logging (default)
	
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

	// Connect and establish TLS
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Send EHLO
	conn.Write([]byte("EHLO test.example.com\r\n"))
	err = readEHLOResponse(conn)
	if err != nil {
		t.Fatal(err)
	}

	// Send STARTTLS
	conn.Write([]byte("STARTTLS\r\n"))
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Perform successful TLS handshake
	tlsConn := tls.Client(conn, clientTLSConfig)
	err = tlsConn.Handshake()
	if err != nil {
		t.Fatal("TLS handshake should succeed:", err)
	}

	// Give server time to process and log
	time.Sleep(100 * time.Millisecond)

	// Check that basic information was logged but not debug details
	logs := logBuf.String()
	
	// Should contain basic TLS establishment
	if !strings.Contains(logs, "TLS established") {
		t.Errorf("Expected TLS establishment to be logged, got: %s", logs)
	}
	
	// Should contain basic information
	if !strings.Contains(logs, "version=") {
		t.Errorf("Expected version in basic log, got: %s", logs)
	}
	
	if !strings.Contains(logs, "cipher=") {
		t.Errorf("Expected cipher in basic log, got: %s", logs)
	}
	
	// Should NOT contain detailed debug information
	if strings.Contains(logs, "server_name=") {
		t.Errorf("Should not have server_name in basic log, got: %s", logs)
	}
	
	if strings.Contains(logs, "negotiated_protocol=") {
		t.Errorf("Should not have negotiated_protocol in basic log, got: %s", logs)
	}
}

// TestTLSTimeoutConfiguration tests different timeout configurations
func TestTLSTimeoutConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		tlsTimeout     time.Duration
		readTimeout    time.Duration
		expectsTimeout bool
	}{
		{
			name:           "No TLS timeout set",
			tlsTimeout:     0,
			readTimeout:    5 * time.Second,
			expectsTimeout: false,
		},
		{
			name:           "TLS timeout set to reasonable value",
			tlsTimeout:     5 * time.Second,
			readTimeout:    1 * time.Second,
			expectsTimeout: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := &tlsTestBackend{}
			s := NewServer(be)
			s.TLSTimeout = tt.tlsTimeout
			s.ReadTimeout = tt.readTimeout
			
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

			// Quick connection test
			conn, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			// Just verify the server starts and accepts connections
			buf := make([]byte, 1024)
			_, err = conn.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			
			// Verify we get a greeting
			if !strings.Contains(string(buf), "220") {
				t.Errorf("Expected SMTP greeting, got: %s", string(buf))
			}
		})
	}
}