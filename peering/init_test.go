package peering

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/frame"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/state"
)

var testData = []byte("The quick brown fox jumps over the lazy dog. ")

func TestPeeringInit(t *testing.T) {
	t.Parallel()

	cA := config.MakeTestConfig(config.Store{
		Router: config.Router{
			Universe:       "test",
			UniverseSecret: "password",
		},
	})
	cB := config.MakeTestConfig(config.Store{
		Router: config.Router{
			Universe:       "test",
			UniverseSecret: "password",
		},
	})

	a := getTestInstance(t, cA)
	b := getTestInstance(t, cB)

	// Initialize connection.
	stateA, msgFromA, err := createPeeringRequest(a, true)
	if err != nil {
		t.Fatal(err)
	}
	stateB, msgFromB, err := createPeeringRequest(b, false)
	if err != nil {
		t.Fatal(err)
	}

	for {
		newMsgFromA, err := stateA.handle(msgFromB)
		if err != nil {
			t.Fatal(err)
		}
		newMsgFromB, err := stateB.handle(msgFromA)
		if err != nil {
			t.Fatal(err)
		}

		msgFromB = newMsgFromB
		msgFromA = newMsgFromA

		if msgFromA == nil && msgFromB == nil {
			break
		}
	}

	// Derive encryption session for link layer.
	linkEncA, err := stateA.finalize()
	if err != nil {
		t.Fatal(err)
	}
	linkEncB, err := stateB.finalize()
	if err != nil {
		t.Fatal(err)
	}

	// Send some messages as test.
	testFrameData := make([]byte, FrameOffset+len(testData)+FrameOverhead)
	testFrame := LinkFrame(testFrameData)
	copy(testFrame.LinkData(), testData)

	for i := 1; i <= 10; i++ {
		if err := testFrame.Seal(linkEncA); err != nil {
			t.Fatalf("%d.a: %s", i, err)
		}
		if err := testFrame.Unseal(linkEncB); err != nil {
			t.Fatalf("%d.b: %s", i, err)
		}
		if err := testFrame.Seal(linkEncB); err != nil {
			t.Fatalf("%d.a: %s", i, err)
		}
		if err := testFrame.Unseal(linkEncA); err != nil {
			t.Fatalf("%d.b: %s", i, err)
		}
	}

	assert.Equal(t, testData, testFrame.LinkData(), "link data must match")
}

func getTestInstance(t *testing.T, c *config.Config) instance {
	t.Helper()

	id, _, err := m.GeneratePrivacyAddress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	instance := &testInstance{
		VersionStub:      "v0.0.0",
		ConfigStub:       c,
		IdentityStub:     id,
		FrameBuilderStub: frame.NewFrameBuilder(),
		RoutingTableStub: m.NewRoutingTable(m.RoutingTableConfig{}),
	}
	stateMgr := state.New(instance, nil)
	instance.StateStub = stateMgr

	// Set margins.
	instance.FrameBuilderStub.SetFrameMargins(FrameOffset, FrameOverhead)

	return instance
}

type testInstance struct {
	VersionStub      string
	ConfigStub       *config.Config
	IdentityStub     *m.Address
	StateStub        *state.State
	FrameBuilderStub *frame.Builder
	RoutingTableStub *m.RoutingTable
}

var _ instance = &testInstance{}

// Version returns the version.
func (stub *testInstance) Version() string {
	return stub.VersionStub
}

// Config returns the config.
func (stub *testInstance) Config() *config.Config {
	return stub.ConfigStub
}

// Identity returns the identity.
func (stub *testInstance) Identity() *m.Address {
	return stub.IdentityStub
}

// State returns the state manager.
func (stub *testInstance) State() *state.State {
	return stub.StateStub
}

// FrameBuilder returns the frame builder.
func (stub *testInstance) FrameBuilder() *frame.Builder {
	return stub.FrameBuilderStub
}

// RoutingTable returns the routing table.
func (stub *testInstance) RoutingTable() *m.RoutingTable {
	return stub.RoutingTableStub
}
