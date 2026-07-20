// Package carrier defines the encrypted WireGuard packet carrier boundary.
package carrier

import "context"

type Carrier interface {
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}
