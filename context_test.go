package smtp_test

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// Test context cancellation in client operations
func TestClientContextCancellation(t *testing.T) {
	be := &backend{}
	s := smtp.NewServer(be)
	s.AllowInsecureAuth = true
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	c, err := smtp.Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Test auth cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = c.AuthContext(ctx, sasl.NewPlainClient("", "username", "password"))
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
}

func TestClientContextTimeout(t *testing.T) {
	be := &backend{}
	s := smtp.NewServer(be)
	s.AllowInsecureAuth = true
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	c, err := smtp.Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Test with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	time.Sleep(5 * time.Millisecond) // Ensure timeout

	err = c.MailContext(ctx, "test@example.com", nil)
	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got %v", err)
	}
}

// Test backend context interfaces
func TestBackendContextSupport(t *testing.T) {
	be := &contextBackend{backend: &backend{}}
	s := smtp.NewServer(be)
	s.AllowInsecureAuth = true
	s.SessionTimeout = 1 * time.Second
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	c, err := smtp.Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// This should work with context-aware backend
	err = c.Mail("test@example.com", nil)
	if err != nil {
		t.Errorf("Expected success with context backend, got %v", err)
	}

	// Verify the backend received the context
	if !be.contextReceived {
		t.Error("Context-aware backend did not receive context")
	}
}

func TestSessionTimeoutEnforcement(t *testing.T) {
	be := &slowBackend{backend: &backend{}}
	s := smtp.NewServer(be)
	s.AllowInsecureAuth = true
	s.SessionTimeout = 100 * time.Millisecond // Very short timeout
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	c, err := smtp.Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Wait for session timeout
	time.Sleep(200 * time.Millisecond)

	// This should fail due to session timeout
	err = c.Mail("test@example.com", nil)
	if err == nil {
		t.Error("Expected timeout error, but operation succeeded")
	}
}

func TestSendMailContextCancellation(t *testing.T) {
	be := &slowBackend{backend: &backend{}}
	s := smtp.NewServer(be)
	s.AllowInsecureAuth = true
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go s.Serve(l)

	c, err := smtp.Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	
	// Start SendMailContext in goroutine
	errChan := make(chan error, 1)
	go func() {
		err := c.SendMailContext(ctx, "test@example.com", []string{"dest@example.com"}, strings.NewReader("Test message"))
		errChan <- err
	}()

	// Cancel after a short delay
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Check that operation was cancelled
	select {
	case err := <-errChan:
		if err != context.Canceled {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("SendMailContext did not respond to cancellation")
	}
}

// Supporting types for context testing

type contextBackend struct {
	*backend
	contextReceived bool
	mu              sync.Mutex
}

func (be *contextBackend) NewSessionContext(ctx context.Context, c *smtp.Conn) (smtp.SessionContext, error) {
	be.mu.Lock()
	be.contextReceived = (ctx != nil)
	be.mu.Unlock()
	
	sess, err := be.backend.NewSession(c)
	if err != nil {
		return nil, err
	}
	return &contextSession{Session: sess}, nil
}

type contextSession struct {
	smtp.Session
}

func (s *contextSession) MailContext(ctx context.Context, from string, opts *smtp.MailOptions) error {
	// Check for cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return s.Session.Mail(from, opts)
}

func (s *contextSession) RcptContext(ctx context.Context, to string, opts *smtp.RcptOptions) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return s.Session.Rcpt(to, opts)
}

func (s *contextSession) DataContext(ctx context.Context, r io.Reader) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return s.Session.Data(r)
}

func (s *contextSession) ResetContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.Session.Reset()
	return nil
}

func (s *contextSession) LogoutContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return s.Session.Logout()
}

type slowBackend struct {
	*backend
}

func (be *slowBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	// Simulate slow session creation
	time.Sleep(50 * time.Millisecond)
	sess, err := be.backend.NewSession(c)
	if err != nil {
		return nil, err
	}
	return &slowSession{Session: sess}, nil
}

type slowSession struct {
	smtp.Session
}

func (s *slowSession) Data(r io.Reader) error {
	// Simulate slow data processing
	time.Sleep(100 * time.Millisecond)
	return s.Session.Data(r)
}