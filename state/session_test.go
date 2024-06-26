package state

import (
	"context"
	mathrand "math/rand"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/mycoria/mycoria/config"
	"github.com/mycoria/mycoria/m"
)

var testData = []byte("The quick brown fox jumps over the lazy dog. ")

func TestKeyExchange(t *testing.T) {
	t.Parallel()

	s1, s2 := getTestSessions(t)
	e1 := s1.Encryption()
	e2 := s2.Encryption()

	// Setup encryption.

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

	// Test Encryption.
	testNonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	testAddition := []byte{13, 14, 15, 16}

	// Client
	msg1 := make([]byte, len(testData)+chacha20poly1305.Overhead)
	copy(msg1, testData)
	msg1 = e1.outCipher.Seal(msg1[:0], testNonce, msg1[:len(testData)], testAddition)
	// Server
	_, err = e2.inCipher.Open(msg1[:0], testNonce, msg1, testAddition)
	if err != nil {
		t.Fatal(err)
	}

	// Server
	msg2 := make([]byte, len(testData)+chacha20poly1305.Overhead)
	copy(msg2, testData)
	msg2 = e2.outCipher.Seal(msg2[:0], testNonce, msg2[:len(testData)], testAddition)
	// Client
	_, err = e1.inCipher.Open(msg2[:0], testNonce, msg2, testAddition)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSequence(t *testing.T) {
	t.Parallel()

	sh1 := NewSequenceHandler()
	sh2 := NewSequenceHandler()

	var (
		batches   = 100
		batchSize = 100
	)
	for i := 0; i < batches; i++ {
		// Create batch.
		numbers := make([]uint32, batchSize)
		for i := 0; i < batchSize; i++ {
			// Create duplicate frame every 10 frames.
			if i != 0 && i%10 == 0 {
				sh1.outSeq.Add(^uint32(0)) // Decrement.
			}
			numbers[i], _ = sh1.NextOut()
		}

		// Shuffle batch!
		mathrand.Shuffle(len(numbers), func(i, j int) {
			numbers[i], numbers[j] = numbers[j], numbers[i]
		})

		// Check and count how many make it.
		var (
			received int
			errs     = make(map[string]int)
		)
		for _, num := range numbers {
			err := sh2.Check(num)
			if err != nil {
				errs[err.Error()]++
			} else {
				received++
			}
		}
		t.Logf("received %d/%d", received, len(numbers))
		for err, cnt := range errs {
			t.Logf("%s: %d", err, cnt)
		}
		if received < 65 {
			t.Errorf("only received %d frames, should at least get 65", received)
		}
		if errs["delayed frame"] == 0 {
			t.Error("should have at least one delayed frame error")
		}
		if errs["delayed duplicate frame"] == 0 {
			t.Error("should have at least one duplicate frame error")
		}
	}
}

func TestTimeSequence(t *testing.T) {
	t.Parallel()

	var (
		sh        = NewTimeSequenceHandler(time.Second)
		batches   = 100
		batchSize = 100
	)
	for i := 0; i < batches; i++ {
		// Create batch.
		times := make([]time.Time, batchSize)
		for i := 0; i < batchSize; i++ {
			t := sh.Next()
			// Create duplicate frame every 10 frames.
			if i != 0 && i%3 == 0 {
				times[i-1] = t
			}
			times[i] = t
		}

		// Shuffle batch!
		mathrand.Shuffle(len(times), func(i, j int) {
			times[i], times[j] = times[j], times[i]
		})

		// Check and count how many make it.
		var (
			received int
			errs     = make(map[string]int)
		)
		for _, timestamp := range times {
			err := sh.Check(timestamp)
			if err != nil {
				errs[err.Error()]++
			} else {
				received++
			}
		}
		t.Logf("received %d/%d", received, len(times))
		for err, cnt := range errs {
			t.Logf("%s: %d", err, cnt)
		}
		if received < 1 {
			t.Errorf("only received %d frames, should at least get 1", received)
		}
		if errs["delayed frame"] == 0 {
			t.Error("should have at least one delayed frame error")
		}
		if errs["immediate duplicate frame"] == 0 {
			t.Error("should have at least one duplicate frame error")
		}
	}
}

var (
	generateTestSessions sync.Once
	generatedS1          *Session
	generatedS2          *Session
)

func getTestSessions(t *testing.T) (s1, s2 *Session) {
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
		state := New(&instanceStub{
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

		generatedS1 = s1
		generatedS2 = s2
	})

	return generatedS1, generatedS2
}

// instanceStub is a stub to easily create an inst.Ance.
type instanceStub struct {
	IdentityStub *m.Address
	ConfigStub   *config.Config
}

// Identity returns the identity.
func (stub *instanceStub) Identity() *m.Address {
	return stub.IdentityStub
}

// Config returns the config.
func (stub *instanceStub) Config() *config.Config {
	return stub.ConfigStub
}
