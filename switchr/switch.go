package switchr

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
	"github.com/mycoria/mycoria/peering"
	"github.com/mycoria/mycoria/state"
)

// Switch handles packets based on switch labels.
type Switch struct {
	input       chan frame.Frame
	routerInput chan frame.Frame

	instance instance
}

// instance is an interface subset of inst.Ance.
type instance interface {
	Version() string
	Config() *config.Config
	Identity() *m.Address
	State() *state.State
	Peering() *peering.Peering
}

// New returns a new switch.
func New(instance instance, upstreamHandler chan frame.Frame) *Switch {
	return &Switch{
		input:       make(chan frame.Frame),
		routerInput: upstreamHandler,
		instance:    instance,
	}
}

// Start starts the switch.
func (s *Switch) Start(mgr *mgr.Manager) error {
	for i := 0; i < runtime.NumCPU(); i++ {
		mgr.StartWorker("switch", s.handler)
	}
	return nil
}

// Stop stops the switch.
func (s *Switch) Stop(mgr *mgr.Manager) error {
	return nil
}

// Input returns the input channel for the switch.
func (s *Switch) Input() chan frame.Frame {
	return s.input
}

func (s *Switch) handler(w *mgr.WorkerCtx) error {
	for {
		select {
		case f := <-s.input:
			if err := s.handleFrame(f); err != nil {
				w.Debug(
					"failed to handle frame",
					"router", f.SrcIP(),
					"err", err,
				)
			}
		case <-w.Done():
			return nil
		}
	}
}

func (s *Switch) handleFrame(f frame.Frame) error {
	// Ignore packets coming from myself.
	if f.SrcIP() == s.instance.Identity().IP {
		return nil
	}

	// Get switch block.
	switchBlock := f.SwitchBlock()
	if len(switchBlock) == 0 {
		return s.escalateFrame(f)
	}

	// Get recv link.
	recvLink := f.RecvLink()
	if recvLink == nil {
		return errors.New("missing recv link")
	}

	// Rotate switch block.
	nextHopLabel, err := m.NextRotateSwitchBlock(switchBlock, recvLink.SwitchLabel())
	if err != nil {
		return fmt.Errorf("rotate switch block: %w", err)
	}

	// Check if we are the destination.
	if nextHopLabel == 0 {
		return s.escalateFrame(f)
	}

	// Forward frame to next hop.
	return s.ForwardByLabel(f, nextHopLabel)
}

func (s *Switch) escalateFrame(f frame.Frame) error {
	select {
	case s.routerInput <- f:
	default:
	}
	return nil
}

// ForwardByLabel forwards a frame by the given switch label.
func (s *Switch) ForwardByLabel(f frame.Frame, nextHopLabel m.SwitchLabel) error {
	// Get link by switch label.
	link := s.instance.Peering().GetLinkByLabel(nextHopLabel)
	if link == nil {
		return errors.New("next hop unavailable")
	}

	return s.forwardToLink(f, link)
}

// ForwardByPeer forwards a frame by the given peer IP.
func (s *Switch) ForwardByPeer(f frame.Frame, peerIP netip.Addr) error {
	// Get link by switch label.
	link := s.instance.Peering().GetLink(peerIP)
	if link == nil {
		return errors.New("next hop unavailable")
	}

	return s.forwardToLink(f, link)
}

func (s *Switch) forwardToLink(f frame.Frame, link peering.Link) error {
	// Decrease and check TTL.
	f.ReduceTTL(1)
	if f.TTL() == 0 {
		return errors.New("TTL expired")
	}

	// Add flow control flag.
	if recvLink := f.RecvLink(); recvLink != nil {
		f.SetFlowFlag(recvLink.FlowControlIndicator())
	}

	// Forward message.
	if f.MessageType().IsPriority() {
		return link.SendPriority(f)
	}
	return link.Send(f)
}
