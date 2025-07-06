package smtp

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// BenchmarkTLSHandshake benchmarks TLS handshake performance
func BenchmarkTLSHandshake(b *testing.B) {
	be := &tlsTestBackend{}
	s := NewServer(be)
	
	// Use valid certificate
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		b.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
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

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Connect to server
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			b.Fatal(err)
		}

		// Read greeting
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}

		// Send EHLO
		conn.Write([]byte("EHLO test.example.com\r\n"))
		err = readEHLOResponse(conn)
		if err != nil {
			b.Fatal(err)
		}

		// Send STARTTLS
		conn.Write([]byte("STARTTLS\r\n"))
		_, err = conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}

		// Perform TLS handshake
		tlsConn := tls.Client(conn, clientTLSConfig)
		err = tlsConn.Handshake()
		if err != nil {
			b.Fatal("TLS handshake failed:", err)
		}

		conn.Close()
	}
}

// BenchmarkTLSHandshakeWithDebug benchmarks TLS handshake with debug logging
func BenchmarkTLSHandshakeWithDebug(b *testing.B) {
	be := &tlsTestBackend{}
	s := NewServer(be)
	s.TLSDebug = true // Enable debug logging
	
	// Use valid certificate
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		b.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
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

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Connect to server
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			b.Fatal(err)
		}

		// Read greeting
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}

		// Send EHLO
		conn.Write([]byte("EHLO test.example.com\r\n"))
		err = readEHLOResponse(conn)
		if err != nil {
			b.Fatal(err)
		}

		// Send STARTTLS
		conn.Write([]byte("STARTTLS\r\n"))
		_, err = conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}

		// Perform TLS handshake
		tlsConn := tls.Client(conn, clientTLSConfig)
		err = tlsConn.Handshake()
		if err != nil {
			b.Fatal("TLS handshake failed:", err)
		}

		conn.Close()
	}
}

// BenchmarkTLSHandshakeWithTimeout benchmarks TLS handshake with timeout configured
func BenchmarkTLSHandshakeWithTimeout(b *testing.B) {
	be := &tlsTestBackend{}
	s := NewServer(be)
	s.TLSTimeout = 5 * time.Second // Set reasonable timeout
	
	// Use valid certificate
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		b.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
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

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Connect to server
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			b.Fatal(err)
		}

		// Read greeting
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}

		// Send EHLO
		conn.Write([]byte("EHLO test.example.com\r\n"))
		err = readEHLOResponse(conn)
		if err != nil {
			b.Fatal(err)
		}

		// Send STARTTLS
		conn.Write([]byte("STARTTLS\r\n"))
		_, err = conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}

		// Perform TLS handshake
		tlsConn := tls.Client(conn, clientTLSConfig)
		err = tlsConn.Handshake()
		if err != nil {
			b.Fatal("TLS handshake failed:", err)
		}

		conn.Close()
	}
}

// BenchmarkTLSStateTransitions benchmarks connection state callbacks during TLS
func BenchmarkTLSStateTransitions(b *testing.B) {
	be := &tlsTestBackend{}
	s := NewServer(be)
	
	// Add state callback to measure overhead
	stateCount := 0
	s.ConnState = func(conn net.Conn, state ConnState) {
		stateCount++
	}
	
	// Use valid certificate
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		b.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
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

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Connect to server
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			b.Fatal(err)
		}

		// Read greeting
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}

		// Send EHLO
		conn.Write([]byte("EHLO test.example.com\r\n"))
		err = readEHLOResponse(conn)
		if err != nil {
			b.Fatal(err)
		}

		// Send STARTTLS
		conn.Write([]byte("STARTTLS\r\n"))
		_, err = conn.Read(buf)
		if err != nil {
			b.Fatal(err)
		}

		// Perform TLS handshake
		tlsConn := tls.Client(conn, clientTLSConfig)
		err = tlsConn.Handshake()
		if err != nil {
			b.Fatal("TLS handshake failed:", err)
		}

		conn.Close()
	}
	
	b.Logf("State transitions per connection: %d", stateCount/b.N)
}

// BenchmarkConcurrentTLSConnections benchmarks multiple concurrent TLS connections
func BenchmarkConcurrentTLSConnections(b *testing.B) {
	be := &tlsTestBackend{}
	s := NewServer(be)
	
	// Use valid certificate
	keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		b.Fatal(err)
	}
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
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

	b.ResetTimer()
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Connect to server
			conn, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				b.Fatal(err)
			}

			// Read greeting
			buf := make([]byte, 1024)
			_, err = conn.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			// Send EHLO
			conn.Write([]byte("EHLO test.example.com\r\n"))
			err = readEHLOResponse(conn)
			if err != nil {
				b.Fatal(err)
			}

			// Send STARTTLS
			conn.Write([]byte("STARTTLS\r\n"))
			_, err = conn.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			// Perform TLS handshake
			tlsConn := tls.Client(conn, clientTLSConfig)
			err = tlsConn.Handshake()
			if err != nil {
				b.Fatal("TLS handshake failed:", err)
			}

			conn.Close()
		}
	})
}