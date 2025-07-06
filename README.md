# go-smtp

[![Go Reference](https://pkg.go.dev/badge/github.com/emersion/go-smtp.svg)](https://pkg.go.dev/github.com/emersion/go-smtp)

An ESMTP client and server library written in Go.

## Features

* ESMTP client & server implementing [RFC 5321]
* Support for additional SMTP extensions such as [AUTH] and [PIPELINING]
* UTF-8 support for subject and message
* [LMTP] support
* Connection lifecycle hooks via `ConnState` callback
* Context support for timeouts, cancellation, and distributed tracing

## Relationship with net/smtp

The Go standard library provides a SMTP client implementation in `net/smtp`.
However `net/smtp` is frozen: it's not getting any new features. go-smtp
provides a server implementation and a number of client improvements.

## Connection Lifecycle Monitoring

The server supports a `ConnState` hook for monitoring connection lifecycle events,
similar to `net/http.Server.ConnState`:

```go
s := smtp.NewServer(backend)
s.ConnState = func(conn net.Conn, state smtp.ConnState) {
    log.Printf("Connection %s: %v", conn.RemoteAddr(), state)
}
```

Available connection states:
- `StateNew` - New connection established
- `StateActive` - Connection ready for SMTP commands
- `StateAuth` - During SASL authentication
- `StateData` - Receiving message data
- `StateStartTLS` - During TLS handshake
- `StateReset` - After RSET command
- `StateIdle` - Between commands
- `StateError` - Connection in error state
- `StateClosed` - Connection closed

## Context Support

The library provides comprehensive context support for both client and server operations, enabling timeout management, operation cancellation, and distributed tracing.

### Server Context Support

#### Session Timeouts

Configure session-level timeouts to limit the total duration of SMTP sessions:

```go
server := smtp.NewServer(backend)
server.SessionTimeout = 30 * time.Second  // Max 30 seconds per session
server.ReadTimeout = 5 * time.Second      // Max 5 seconds per command
server.WriteTimeout = 5 * time.Second     // Max 5 seconds for responses
```

- `SessionTimeout`: Maximum duration for the entire session (connection to completion)
- Setting to `0` disables session-level timeout (only per-operation timeouts apply)
- Session timeout is independent of `ReadTimeout` and `WriteTimeout`

#### Context-Aware Backends

Implement the `BackendContext` interface for advanced context support:

```go
type MyBackend struct{}

func (b *MyBackend) NewSessionContext(ctx context.Context, c *smtp.Conn) (smtp.SessionContext, error) {
    // Session context carries the server's session timeout
    return &MySession{ctx: ctx}, nil
}

type MySession struct {
    ctx context.Context
}

func (s *MySession) MailContext(ctx context.Context, from string, opts *smtp.MailOptions) error {
    // Check if context was cancelled
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    
    // Your mail processing logic here
    return nil
}

func (s *MySession) RcptContext(ctx context.Context, to string, opts *smtp.RcptOptions) error {
    // Context-aware recipient processing
    return nil
}

func (s *MySession) DataContext(ctx context.Context, r io.Reader) error {
    // Context-aware data processing
    return nil
}
```

The `SessionContext` interface extends the regular `Session` interface with context-aware methods. The library automatically falls back to non-context methods if `BackendContext` is not implemented.

### Client Context Support

All client operations have context-aware variants:

```go
client, err := smtp.Dial("localhost:25")
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Create a context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

// Context-aware operations
err = client.AuthContext(ctx, auth)
err = client.MailContext(ctx, "sender@example.com", nil)
err = client.RcptContext(ctx, "recipient@example.com", nil)

// Send mail with context
err = client.SendMailContext(ctx, "sender@example.com", 
    []string{"recipient@example.com"}, messageReader)
```

#### Timeout Behavior

- **Client timeouts**: Context deadline is combined with `CommandTimeout` (whichever is sooner)
- **Cancellation**: Operations can be cancelled mid-flight through context cancellation
- **Data transfer**: Large message transfers respect context cancellation between operations

### Use Cases

- **Request timeouts**: Set per-request timeouts for client operations
- **Server limits**: Prevent long-running sessions from consuming resources
- **Cancellation**: Cancel operations when clients disconnect or requests are aborted
- **Distributed tracing**: Propagate trace information through the context
- **Graceful shutdown**: Use context cancellation for clean server shutdown

### Backwards Compatibility

Context support is fully backwards compatible:
- Existing `Backend` implementations continue to work unchanged
- Non-context client methods use `context.Background()` internally
- Libraries can migrate to context support incrementally

## Licence

MIT

[RFC 5321]: https://tools.ietf.org/html/rfc5321
[AUTH]: https://tools.ietf.org/html/rfc4954
[PIPELINING]: https://tools.ietf.org/html/rfc2920
[LMTP]: https://tools.ietf.org/html/rfc2033
