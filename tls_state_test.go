package smtp

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"
)

// TestTLSStateTransitions tests the granular TLS state transitions
func TestTLSStateTransitions(t *testing.T) {
	// Track state transitions
	var mu sync.Mutex
	var states []ConnState
	
	be := &tlsTestBackend{}
	s := NewServer(be)
	
	// Use valid certificate for successful handshake
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	
	// Set up state tracking
	s.ConnState = func(conn net.Conn, state ConnState) {
		mu.Lock()
		states = append(states, state)
		mu.Unlock()
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

	// Give server time to process state changes
	time.Sleep(200 * time.Millisecond)

	// Verify state transitions
	mu.Lock()
	statesCopy := make([]ConnState, len(states))
	copy(statesCopy, states)
	mu.Unlock()

	// Expected state transitions for successful TLS:
	// StateNew -> StateActive -> StateStartTLS -> StateTLSSuccess -> StateActive
	expectedStates := []ConnState{StateNew, StateActive, StateStartTLS, StateTLSSuccess, StateActive}
	
	if len(statesCopy) < len(expectedStates) {
		t.Fatalf("Expected at least %d state transitions, got %d: %v", len(expectedStates), len(statesCopy), statesCopy)
	}

	// Check that we have the expected state sequence (allowing for additional states)
	stateIndex := 0
	for i, expectedState := range expectedStates {
		found := false
		for j := stateIndex; j < len(statesCopy); j++ {
			if statesCopy[j] == expectedState {
				found = true
				stateIndex = j + 1
				break
			}
		}
		if !found {
			t.Errorf("Expected state %v at position %d or later, but not found in sequence: %v", expectedState, i, statesCopy)
		}
	}

	// Specifically verify we got the granular TLS states
	hasStartTLS := false
	hasTLSSuccess := false
	for _, state := range statesCopy {
		if state == StateStartTLS {
			hasStartTLS = true
		}
		if state == StateTLSSuccess {
			hasTLSSuccess = true
		}
	}

	if !hasStartTLS {
		t.Error("Expected StateStartTLS in state transitions")
	}
	if !hasTLSSuccess {
		t.Error("Expected StateTLSSuccess in state transitions")
	}
}

// TestTLSFailureStateTransitions tests state transitions for failed TLS handshakes
func TestTLSFailureStateTransitions(t *testing.T) {
	// Track state transitions
	var mu sync.Mutex
	var states []ConnState
	
	be := &tlsTestBackend{}
	s := NewServer(be)
	s.TLSConfig = &tls.Config{
		// Use invalid certificate to force handshake error
		Certificates: []tls.Certificate{},
	}
	
	// Set up state tracking
	s.ConnState = func(conn net.Conn, state ConnState) {
		mu.Lock()
		states = append(states, state)
		mu.Unlock()
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

	// Try to start TLS handshake (this should fail due to invalid cert)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: false, // Force certificate validation
	})
	
	// This should trigger handshake error on server side
	tlsConn.Handshake()
	
	// Give server time to process state changes
	time.Sleep(200 * time.Millisecond)

	// Verify state transitions
	mu.Lock()
	statesCopy := make([]ConnState, len(states))
	copy(statesCopy, states)
	mu.Unlock()

	// Expected state transitions for failed TLS:
	// StateNew -> StateActive -> StateStartTLS -> StateTLSFailed -> StateError
	hasStartTLS := false
	hasTLSFailed := false
	hasError := false
	
	for _, state := range statesCopy {
		if state == StateStartTLS {
			hasStartTLS = true
		}
		if state == StateTLSFailed {
			hasTLSFailed = true
		}
		if state == StateError {
			hasError = true
		}
	}

	if !hasStartTLS {
		t.Error("Expected StateStartTLS in state transitions")
	}
	if !hasTLSFailed {
		t.Error("Expected StateTLSFailed in state transitions")
	}
	if !hasError {
		t.Error("Expected StateError in state transitions")
	}

	// Verify correct order: StateTLSFailed should come before StateError
	tlsFailedIndex := -1
	errorIndex := -1
	for i, state := range statesCopy {
		if state == StateTLSFailed && tlsFailedIndex == -1 {
			tlsFailedIndex = i
		}
		if state == StateError && errorIndex == -1 {
			errorIndex = i
		}
	}

	if tlsFailedIndex >= 0 && errorIndex >= 0 && tlsFailedIndex >= errorIndex {
		t.Errorf("StateTLSFailed should come before StateError, got states: %v", statesCopy)
	}
}

// TestBackwardsCompatibilityTLSStates ensures existing ConnState callbacks still work
func TestBackwardsCompatibilityTLSStates(t *testing.T) {
	// Track state transitions
	var mu sync.Mutex
	var states []ConnState
	
	be := &tlsTestBackend{}
	s := NewServer(be)
	
	// Use valid certificate for successful handshake
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	
	// Legacy ConnState callback - should still receive StateActive and StateError
	s.ConnState = func(conn net.Conn, state ConnState) {
		mu.Lock()
		states = append(states, state)
		mu.Unlock()
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

	// Give server time to process state changes
	time.Sleep(200 * time.Millisecond)

	// Verify backwards compatibility - existing callbacks should still get StateActive
	mu.Lock()
	statesCopy := make([]ConnState, len(states))
	copy(statesCopy, states)
	mu.Unlock()

	// Should still have StateActive after successful TLS (backwards compatibility)
	hasStateActive := false
	for _, state := range statesCopy {
		if state == StateActive {
			hasStateActive = true
			break
		}
	}

	if !hasStateActive {
		t.Errorf("Expected StateActive for backwards compatibility, got states: %v", statesCopy)
	}
}