package peering

import (
	"net"
	"sync/atomic"

	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

// Listener represents a network connection listener.
type Listener interface {
	// ID returns the listener ID.
	ID() string

	// PeeringURL returns the used peering URL.
	PeeringURL() *m.PeeringURL

	// ListenAddress returns the used listen address.
	ListenAddress() net.Addr

	// Close closes the underlying listener and cleans up any related resources.
	Close(log func())
}

// ListenerBase implements common functions to comply with the Listener interface.
type ListenerBase struct {
	id string

	// listener is the actual underlying listener.
	listener net.Listener

	// peeringURL holds the used peering URL.
	peeringURL *m.PeeringURL
	// closing specifies if the link is being closed
	closing atomic.Bool

	// peering references back to the peering manager.
	peering *Peering
}

var _ Listener = &ListenerBase{}

func newListenerBase(
	id string,
	listener net.Listener,
	peeringURL *m.PeeringURL,
	peering *Peering,
) *ListenerBase {
	return &ListenerBase{
		id:         id,
		listener:   listener,
		peeringURL: peeringURL,
		peering:    peering,
	}
}

func (ln *ListenerBase) startWorkers() {
	ln.peering.mgr.StartWorker("listener", ln.listenWorker)
}

// ID returns the listener ID.
func (ln *ListenerBase) ID() string {
	return ln.id
}

// PeeringURL returns the used peering URL.
func (ln *ListenerBase) PeeringURL() *m.PeeringURL {
	return ln.peeringURL
}

// ListenAddress returns the listen address.
func (ln *ListenerBase) ListenAddress() net.Addr {
	return ln.listener.Addr()
}

// Close closes the listener.
func (ln *ListenerBase) Close(log func()) {
	if ln == nil {
		return
	}

	if ln.closing.CompareAndSwap(false, true) {
		if log != nil {
			log()
		}

		ln.peering.RemoveListener(ln.id)
		_ = ln.listener.Close()
	}
}

func (ln *ListenerBase) listenWorker(w *mgr.WorkerCtx) error {
	defer ln.Close(func() {
		w.Info(
			"closing listener (by listener)",
			"peeringURL", ln.PeeringURL(),
			"bind", ln.ListenAddress(),
		)
	})

	for {
		conn, err := ln.listener.Accept()
		if err != nil {
			ln.Close(func() {
				w.Warn(
					"accept error, closing listener",
					"peeringURL", ln.PeeringURL(),
					"bind", ln.ListenAddress(),
				)
			})
			return nil //nolint:nilerr // Worker has no error.
		}

		if conn == nil {
			return nil
		}

		newLink := newLinkBase(
			conn,
			ln.peeringURL,
			false,
			ln.peering,
		)
		ln.peering.mgr.StartWorker("setup link", newLink.setupWorker)
	}
}
