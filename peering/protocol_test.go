package peering

import (
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slog"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/mgr"
)

var testRequest = "hello world"

func TestProtocol(t *testing.T) {
	t.Parallel()

	// Configure logging.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))

	// Build peering instances.
	c := config.MakeTestConfig(config.Store{
		Router: config.Router{
			Universe:       "test",
			UniverseSecret: "password",
		},
	})
	i1 := getTestInstance(t, c)
	i2 := getTestInstance(t, c)
	p1 := New(i1, make(chan frame.Frame))
	p2 := New(i2, make(chan frame.Frame))

	err := p1.Start(mgr.New("peering1"))
	if err != nil {
		t.Fatal(err)
	}
	err = p2.Start(mgr.New("peering2"))
	if err != nil {
		t.Fatal(err)
	}

	// Handle frames to receive result.
	var (
		result1  string
		arrived1 = make(chan struct{})
	)
	go func() {
		f := <-p1.frameHandler
		result1 = string(f.MessageData())
		close(arrived1)
	}()

	// Add pipe protocol for testing.
	pipe1, pipe2 := NewConnectedPipeStacks()
	p1.AddProtocol("pipe", pipe1)
	p2.AddProtocol("pipe", pipe2)

	// Start listener.
	_, err = p1.StartListener(&m.PeeringURL{Protocol: "pipe"}, netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}

	// Connect to listener.
	link, err := p2.PeerWith(&m.PeeringURL{Protocol: "pipe"}, netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}

	testFrame, err := i2.FrameBuilder().NewFrameV1(
		m.RouterAddress,
		m.RouterAddress,
		frame.NetworkTraffic,
		nil,
		[]byte(testRequest),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = link.Send(testFrame)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for message to arrive.
	<-arrived1
	assert.Equal(t, testRequest, result1, "result must match")
	t.Log("received test message!")

	err = p1.Stop(p1.mgr)
	if err != nil {
		t.Fatal(err)
	}
	err = p2.Stop(p2.mgr)
	if err != nil {
		t.Fatal(err)
	}
}
