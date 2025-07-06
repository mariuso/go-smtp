package smtp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// Simple backend for TLS testing
type tlsTestBackend struct{}

func (be *tlsTestBackend) NewSession(_ *Conn) (Session, error) {
	return &tlsTestSession{}, nil
}

type tlsTestSession struct{}

func (s *tlsTestSession) Mail(from string, opts *MailOptions) error {
	return nil
}

func (s *tlsTestSession) Rcpt(to string, opts *RcptOptions) error {
	return nil
}

func (s *tlsTestSession) Data(r io.Reader) error {
	io.Copy(io.Discard, r)
	return nil
}

func (s *tlsTestSession) Reset() {}

func (s *tlsTestSession) Logout() error {
	return nil
}

// Helper function to read EHLO response (which may be multi-line)
func readEHLOResponse(conn net.Conn) error {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		response := string(buf[:n])
		if strings.Contains(response, "250 ") { // Final line
			break
		}
	}
	return nil
}

// TestTLSHandshakeError tests detailed error logging for TLS handshake failures
func TestTLSHandshakeError(t *testing.T) {
	// Capture error logs
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "test: ", 0)

	be := &tlsTestBackend{}
	s := NewServer(be)
	s.ErrorLog = logger
	s.TLSConfig = &tls.Config{
		// Use invalid certificate to force handshake error
		Certificates: []tls.Certificate{},
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
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	
	if !strings.Contains(string(buf[:n]), "220") {
		t.Fatalf("Expected TLS ready response, got: %s", string(buf[:n]))
	}

	// Try to start TLS handshake (this should fail due to invalid cert)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: false, // Force certificate validation
	})
	
	// This should trigger handshake error on server side
	tlsConn.Handshake()
	
	// Give server time to process and log the error
	time.Sleep(100 * time.Millisecond)

	// Check that detailed error was logged
	logs := logBuf.String()
	if !strings.Contains(logs, "TLS handshake failed") {
		t.Errorf("Expected detailed TLS error to be logged, got: %s", logs)
	}
	
	if !strings.Contains(logs, "127.0.0.1") {
		t.Errorf("Expected remote address in error log, got: %s", logs)
	}
}

// TestTLSSuccessLogging tests that successful TLS establishment is logged
func TestTLSSuccessLogging(t *testing.T) {
	// Capture error logs
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "test: ", 0)

	be := &tlsTestBackend{}
	s := NewServer(be)
	s.ErrorLog = logger
	
	// Use valid certificate for successful handshake
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

	// Check that success was logged
	logs := logBuf.String()
	if !strings.Contains(logs, "TLS established") {
		t.Errorf("Expected TLS success to be logged, got: %s", logs)
	}
	
	if !strings.Contains(logs, "version=") {
		t.Errorf("Expected TLS version in success log, got: %s", logs)
	}
	
	if !strings.Contains(logs, "cipher=") {
		t.Errorf("Expected cipher suite in success log, got: %s", logs)
	}
}

// TestTLSErrorMessage tests that error messages are more descriptive
func TestTLSErrorMessage(t *testing.T) {
	be := &tlsTestBackend{}
	s := NewServer(be)
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{}, // Invalid config
	}
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 1024)
	conn.Read(buf)

	// Send EHLO
	conn.Write([]byte("EHLO test.example.com\r\n"))
	readEHLOResponse(conn)

	// Send STARTTLS
	conn.Write([]byte("STARTTLS\r\n"))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	response := string(buf[:n])
	if !strings.Contains(response, "220") {
		t.Fatalf("Expected TLS ready response, got: %s", response)
	}

	// Try TLS handshake that will fail
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: false,
	})
	
	tlsConn.Handshake() // This will fail
	
	// Read the error response
	n, err = conn.Read(buf)
	if err == nil {
		response = string(buf[:n])
		// Should get improved error message
		if strings.Contains(response, "Handshake error") {
			t.Errorf("Got old generic error message: %s", response)
		}
		if !strings.Contains(response, "TLS handshake failed") {
			t.Errorf("Expected improved error message 'TLS handshake failed', got: %s", response)
		}
	}
}

// TestTLSNotSupported tests the case where TLS is not configured
func TestTLSNotSupported(t *testing.T) {
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "test: ", 0)

	be := &tlsTestBackend{}
	s := NewServer(be)
	s.ErrorLog = logger
	// Don't set TLSConfig - TLS not supported
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 1024)
	conn.Read(buf)

	// Send EHLO
	conn.Write([]byte("EHLO test.example.com\r\n"))
	readEHLOResponse(conn)

	// Send STARTTLS when not supported
	conn.Write([]byte("STARTTLS\r\n"))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	response := string(buf[:n])
	if !strings.Contains(response, "502") || !strings.Contains(response, "TLS not supported") {
		t.Errorf("Expected '502 TLS not supported', got: %s", response)
	}

	// Should not have any TLS-related error logs since TLS wasn't attempted
	logs := logBuf.String()
	if strings.Contains(logs, "TLS handshake failed") {
		t.Errorf("Should not have TLS handshake error when TLS not supported, got: %s", logs)
	}
}