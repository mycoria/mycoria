package frame

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
	"github.com/mycoria/mycoria/state"
)

var (
	testData          = []byte("The quick brown fox jumps over the lazy dog. ")
	testSeqNum uint32 = 123456789
	testSeqAck uint32 = 987654321

	testFrameV1 = []byte{
		/* 00 */ 0x01, 0xff, 0x02, 0x63, 0x01, 0x00, 0x00, 0x00 /**/, 0x07, 0x5b, 0xcd, 0x15, 0x3a, 0xde, 0x68, 0xb1, // |...c...+.[..:.h.|
		/* 10 */ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /**/, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // |................|
		/* 20 */ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /**/, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // |................|
		/* 30 */ 0x2d, 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69 /**/, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, // |-The quick brown|
		/* 40 */ 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d /**/, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, // | fox jumps over |
		/* 50 */ 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79 /**/, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x00, 0x2d, // |the lazy dog. .-|
		/* 60 */ 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63 /**/, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, // |The quick brown |
		/* 70 */ 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70 /**/, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, // |fox jumps over t|
		/* 80 */ 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20 /**/, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x00, 0x00, 0x00, // |he lazy dog. ...|
		/* 90 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /**/, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // |................|
		/* a0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /**/, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // |................|
		/* b0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /**/, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // |................|
		/* c0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /**/, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x68, 0x65, // |.............The|
		/* d0 */ 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62 /**/, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, // | quick brown fox|
		/* e0 */ 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f /**/, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, // | jumps over the |
		/* f0 */ 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67 /**/, 0x2e, 0x20, // |lazy dog. |
	}
)

func TestFrameV1(t *testing.T) {
	t.Parallel()

	// Build frame.
	b := NewFrameBuilder()
	b.SetFrameMargins(12, 16)
	f, err := b.NewFrameV1(
		netip.IPv6LinkLocalAllNodes(),
		netip.IPv6LinkLocalAllRouters(),
		RouterPing,
		testData,
		testData,
		testData,
	)
	if err != nil {
		t.Fatal(err)
	}
	f.SetSequenceNum(testSeqNum)
	f.SetSequenceAck(testSeqAck)
	f.SetFlowFlag(FlowControlFlagHoldFlow)
	f.SetRecvRate(99)
	f.SetTTL(255)
	// Remove random nonce for comparison.
	clear(f.data[5:8])

	// DEBUG: Print built frame.
	// fmt.Println(hex.Dump(f.data))

	// Check against test frame.
	assert.Equal(t, testFrameV1, f.data, "frames should match")

	// Copy frame data to simulate transfer.
	copied := b.GetPooledSlice(len(f.pooledSlice))
	copy(copied, f.pooledSlice)

	// Parse frame again.
	f2, err := b.ParseFrame(copied[f.psDataOffset:f.psDataOffset+len(f.data)], copied, f.psDataOffset)
	if err != nil {
		t.Fatal(err)
	}

	// Check if we can the frame with the margins we want.
	start := 12 + frameV1SwitchBlockIndex + frameV1SwitchBlockLengthSize
	end := start + len(testData)
	withMargins1, err := f.FrameDataWithMargins(12, 16)
	if err != nil {
		t.Fatal(err)
	}
	withMargins2, err := f2.FrameDataWithMargins(12, 16)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, testData, withMargins1[start:end], "data with margins (1) must match")
	assert.Equal(t, testData, withMargins2[start:end], "data with margins (2) must match")

	// Make a detailed comparison.

	assert.Equal(t, uint8(V1), f.Version(), "version should match")
	assert.Equal(t, uint8(V1), f2.Version(), "version should match")

	assert.Equal(t, uint8(255), f.TTL(), "TTL should match")
	assert.Equal(t, uint8(255), f2.TTL(), "TTL should match")

	assert.Equal(t, false, f.HasFlowFlag(FlowControlFlagDecreaseFlow), "flow control should match")
	assert.Equal(t, false, f2.HasFlowFlag(FlowControlFlagDecreaseFlow), "flow control should match")
	assert.Equal(t, true, f.HasFlowFlag(FlowControlFlagHoldFlow), "flow control should match")
	assert.Equal(t, true, f2.HasFlowFlag(FlowControlFlagHoldFlow), "flow control should match")
	assert.Equal(t, false, f.HasFlowFlag(FlowControlFlagIncreaseFlow), "flow control should match")
	assert.Equal(t, false, f2.HasFlowFlag(FlowControlFlagIncreaseFlow), "flow control should match")

	assert.Equal(t, RouterPing, f.MessageType(), "message type should match")
	assert.Equal(t, RouterPing, f2.MessageType(), "message type should match")

	assert.Equal(t, testSeqNum, f.SequenceNum(), "sequence numbers should match")
	assert.Equal(t, testSeqNum, f2.SequenceNum(), "sequence numbers should match")

	assert.Equal(t, testSeqAck, f.SequenceAck(), "sequence acks should match")
	assert.Equal(t, testSeqAck, f2.SequenceAck(), "sequence acks should match")

	assert.Equal(t, netip.IPv6LinkLocalAllNodes(), f.SrcIP(), netip.IPv6LinkLocalAllNodes(), "src IP should match")
	assert.Equal(t, netip.IPv6LinkLocalAllNodes(), f2.SrcIP(), netip.IPv6LinkLocalAllNodes(), "src IP should match")

	assert.Equal(t, netip.IPv6LinkLocalAllRouters(), f.DstIP(), netip.IPv6LinkLocalAllRouters(), "dst IP should match")
	assert.Equal(t, netip.IPv6LinkLocalAllRouters(), f2.DstIP(), netip.IPv6LinkLocalAllRouters(), "dst IP should match")

	assert.Equal(t, testData, f.SwitchBlock(), "switch block should match")
	assert.Equal(t, testData, f2.SwitchBlock(), "switch block should match")

	assert.Equal(t, testData, f.MessageData(), "message data should match")
	assert.Equal(t, testData, f2.MessageData(), "message data should match")

	assert.Equal(t, testData, f.AppendixData(), "appendix data should match")
	assert.Equal(t, testData, f2.AppendixData(), "appendix data should match")

	// Test signing and encryption.

	s1, s2 := getTestSessions(t)

	for _, msgType := range []MessageType{
		RouterHopPing,
		RouterPing,
		RouterCtrl,
		NetworkTraffic,
		SessionCtrl,
		SessionData,
	} {
		// Reset frame for next msg type test.
		err = f.initFrame(
			s1.Address().IP, s2.Address().IP, msgType,
			testData, testData, testData,
		)
		if err != nil {
			t.Fatalf("failed to init frame %s: %s", msgType, err)
		}
		clear(f.authData())

		// Router identity is s1.
		if err := f.Seal(s2); err != nil { // Seal for s2.
			t.Fatalf("failed to seal %s: %s", msgType, err)
		}
		if err := f.Unseal(s1); err != nil { // Unseal from s1.
			t.Fatalf("failed to unseal %s: %s", msgType, err)
		}

		// Wait for 2ms, because the signature sequence is ms based.
		time.Sleep(2 * time.Millisecond)
	}

	f.ReturnToPool()
	f2.ReturnToPool()
}

func TestKeyRollover(t *testing.T) { //nolint:paralleltest // Key iteration must be done exlusively.
	// Setup.
	b := NewFrameBuilder()
	s1, s2 := getTestSessions(t)
	e1h := state.EncryptionSessionTestHelper{
		EncryptionSession: s1.Encryption(),
	}
	e2h := state.EncryptionSessionTestHelper{
		EncryptionSession: s2.Encryption(),
	}
	e1h.ReglSetOut(0xFFFF_FFFF - 50)
	e1h.PrioSetOut(0xFFFF)
	e2h.PrioSetOut(0xFFFF)
	s1OldOutKey := e1h.OutKey()
	s2OldInKey := e2h.InKey()

	// Create test frame.
	f, err := b.NewFrameV1(
		s1.Address().IP,
		s2.Address().IP,
		NetworkTraffic,
		testData,
		testData,
		testData,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt 100 frames, and roll over the sequence number and keys.
	for i := 0; i < 100; i++ {
		// Clear auth data.
		clear(f.authData())

		if err := f.Seal(s1); err != nil {
			t.Fatalf("failed to seal at %d: %s", i, err)
		}
		if err := f.Unseal(s2); err != nil {
			assert.NotEqual(t, e1h.OutKey(), s1OldOutKey, "s1 out key should have changed")
			assert.NotEqual(t, e2h.InKey(), s2OldInKey, "s2 in key should have changed")
			t.Fatalf("failed to unseal at %d: %s", i, err)
		}
	}

	nextReglSeq, _ := e1h.ReglSeq().NextOut()
	nextPrioSeq, _ := e1h.PrioSeq().NextOut()
	assert.Equal(t, 51, int(nextReglSeq), "regl seq did not roll over")
	assert.Equal(t, 1, int(nextPrioSeq), "prio seq did not roll over")
	recvReglSeq, _ := e2h.ReglSeq().Ack()
	recvPrioSeq, _ := e2h.PrioSeq().Ack()
	assert.Equal(t, 50, int(recvReglSeq), "regl seq did not roll over on receiver")
	assert.Equal(t, 0, int(recvPrioSeq), "prio seq did not roll over on receiver")

	assert.NotEqual(t, e1h.OutKey(), s1OldOutKey, "s1 out key should have changed")
	assert.NotEqual(t, e2h.InKey(), s2OldInKey, "s2 in key should have changed")
}

// TODO: Delete if not used anymore.
// var (
// 	fakeSrc         = netip.MustParseAddr(gofakeit.IPv6Address())
// 	fakeDst         = netip.MustParseAddr(gofakeit.IPv6Address())
// 	fakeSwitchBlock = []byte{1, 2, 3, 4, 5}
// )

// func fakeFrame(b *Builder, msgType MessageType) *FrameV1 {
// 	f, err := b.NewFrameV1(
// 		fakeSrc,
// 		fakeDst,
// 		msgType,
// 		fakeSwitchBlock,
// 		testData,
// 		nil,
// 	)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return f
// }

var (
	generateTestSessions sync.Once
	generatedS1          *state.Session
	generatedS2          *state.Session
)

func getTestSessions(t *testing.T) (s1, s2 *state.Session) {
	t.Helper()

	generateTestSessions.Do(func() {
		ctx := context.Background()
		config := &config.Config{}

		a1, _, err := m.GeneratePrivacyAddress(ctx)
		if err != nil {
			t.Fatal(err)
		}
		a2, _, err := m.GeneratePrivacyAddress(ctx)
		if err != nil {
			t.Fatal(err)
		}
		state := state.New(&instanceStub{
			IdentityStub: a1,
			ConfigStub:   config,
		}, nil)
		err = state.AddRouter(&a1.PublicAddress)
		if err != nil {
			t.Fatal(err)
		}
		err = state.AddRouter(&a2.PublicAddress)
		if err != nil {
			t.Fatal(err)
		}

		s1 = state.GetSession(a1.IP)
		if s1 == nil {
			t.Fatal("failed to get session 1")
		}
		s2 = state.GetSession(a2.IP)
		if s1 == nil {
			t.Fatal("failed to get session 2")
		}

		// Setup encryption.
		e1 := s1.Encryption()
		e2 := s2.Encryption()
		// Client
		kxKey1, kxType1, err := e1.InitKeyClientStart()
		if err != nil {
			t.Fatal(err)
		}
		// Server
		kxKey2, kxType2, err := e2.InitKeyServer(kxKey1, kxType1)
		if err != nil {
			t.Fatal(err)
		}
		// Client
		err = e1.InitKeyClientComplete(kxKey2, kxType2)
		if err != nil {
			t.Fatal(err)
		}

		generatedS1 = s1
		generatedS2 = s2
	})

	return generatedS1, generatedS2
}

// instanceStub is a stub to easily create an inst.Ance.
type instanceStub struct {
	VersionStub      string
	UniverseStub     string
	IdentityStub     *m.Address
	ConfigStub       *config.Config
	FrameBuilderStub *Builder
	StateStub        *state.State
}

// Version returns the version.
func (stub *instanceStub) Version() string {
	return stub.VersionStub
}

// Universe returns the universe.
func (stub *instanceStub) Universe() string {
	return stub.UniverseStub
}

// Identity returns the identity.
func (stub *instanceStub) Identity() *m.Address {
	return stub.IdentityStub
}

// Config returns the config.
func (stub *instanceStub) Config() *config.Config {
	return stub.ConfigStub
}

// FrameBuilder returns the frame builder.
func (stub *instanceStub) FrameBuilder() *Builder {
	return stub.FrameBuilderStub
}

// State returns the state manager.
func (stub *instanceStub) State() *state.State {
	return stub.StateStub
}
