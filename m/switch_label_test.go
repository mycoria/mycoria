package m

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit"
	"github.com/stretchr/testify/assert"
)

type hopTestData struct {
	FwdHops   []SwitchLabel
	RetHops   []SwitchLabel
	BlockSize int
}

func TestSwitchLabels(t *testing.T) { //nolint:tparallel // Faster without.
	t.Parallel()

	testSet := []hopTestData{
		{ // Manual.
			FwdHops:   []SwitchLabel{67, 1, 123, 15, 0},
			RetHops:   []SwitchLabel{3, 3, 128, 16383, 0},
			BlockSize: 6,
		},
		{ // Manually constructed edge case.
			FwdHops:   []SwitchLabel{1, 1, 16383, 1, 16383, 0},
			RetHops:   []SwitchLabel{1, 1, 16383, 16383, 16383, 0},
			BlockSize: 9,
		},
		{ // Manually constructed edge case.
			FwdHops:   []SwitchLabel{16383, 16383, 1, 1, 0},
			RetHops:   []SwitchLabel{16383, 16383, 1, 1, 0},
			BlockSize: 6,
		},
		{ // From previously failing random test.
			FwdHops:   []SwitchLabel{87, 39, 684, 43, 485, 0},
			RetHops:   []SwitchLabel{108, 105, 968, 150, 941, 0},
			BlockSize: 9,
		},
		{ // From previously failing random test.
			FwdHops:   []SwitchLabel{736, 105, 263, 0},
			RetHops:   []SwitchLabel{756, 997, 292, 0},
			BlockSize: 6,
		},
	}

	// This is how the first test set looks in the common form.
	// var (
	// 	testSwitchPath = &SwitchPath{
	// 		Hops: []SwitchHop{{
	// 			// Self.
	// 			ForwardLabel: 67, //0x43
	// 			ReturnLabel:  0,
	// 		}, {
	// 			ForwardLabel: 1,
	// 			ReturnLabel:  16383, // 0xFF7F
	// 		}, {
	// 			ForwardLabel: 123, // 0x7B
	// 			ReturnLabel:  128, // 0x8001
	// 		}, {
	// 			ForwardLabel: 15, // 0x0F
	// 			ReturnLabel:  3,
	// 		}, {
	// 			ForwardLabel: 0,
	// 			ReturnLabel:  3,
	// 		}},
	// 	}
	// 	testBlockSize = 6
	// )

	for _, test := range testSet { //nolint:paralleltest // Faster without.
		td := test
		t.Run("testing random switch path", func(t *testing.T) {
			testSwitchPathFromSlices(t, td.FwdHops, td.RetHops, td.BlockSize)
		})
	}
}

func TestRandomSwitchLabels(t *testing.T) { //nolint:tparallel // Faster without.
	t.Parallel()

	var (
		runs     = 1000
		maxLabel = MaxPrivateSwitchLabel
	)
	for i := 0; i < runs; i++ {
		// Get random hop count - 3-10 Hops.
		hopCnt := gofakeit.Number(3, 10)
		// Generate random hops.
		hops := make([]SwitchHop, hopCnt)
		for i := 0; i < hopCnt; i++ {
			switch i {
			case 0:
				// Start switch.
				hops[i] = SwitchHop{
					ForwardLabel: SwitchLabel(gofakeit.Number(1, maxLabel)),
					ReturnLabel:  0,
				}
			case hopCnt - 1:
				// End switch.
				hops[i] = SwitchHop{
					ForwardLabel: 0,
					ReturnLabel:  SwitchLabel(gofakeit.Number(1, maxLabel)),
				}
			default:
				// Middle switch
				hops[i] = SwitchHop{
					ForwardLabel: SwitchLabel(gofakeit.Number(1, maxLabel)),
					ReturnLabel:  SwitchLabel(gofakeit.Number(1, maxLabel)),
				}
			}
		}
		// Test path.
		t.Run("testing random switch path", func(t *testing.T) { //nolint:paralleltest // Faster without.
			testSwitchPath(t, hops, 0)
		})
	}
}

func testSwitchPathFromSlices(t *testing.T, fwdHops, retHops []SwitchLabel, expectedBlockSize int) {
	t.Helper()

	// Check hop count.
	if len(fwdHops) != len(retHops) {
		t.Fatal("forward and return hop count does not match")
	}

	// Convert to switch hops.
	hops := make([]SwitchHop, len(fwdHops))
	for i := 0; i < len(hops); i++ {
		hops[i].ForwardLabel = fwdHops[i]
		hops[i].ReturnLabel = retHops[len(hops)-i-1]
	}

	// Start testing.
	testSwitchPath(t, hops, expectedBlockSize)
}

func testSwitchPath(t *testing.T, hops []SwitchHop, expectedBlockSize int) {
	t.Helper()

	// Create switch path struct.
	switchPath := &SwitchPath{Hops: hops}
	t.Logf("testing switch path: %+v", formatSwitchPath(switchPath))
	// t.Logf("testing switch path: %+v", switchPath)

	// Check block size and build blocks.
	if expectedBlockSize > 0 {
		blockSize, err := switchPath.CalculateBlockSize()
		if err != nil {
			t.Fatal(err)
		}
		if !assert.Equal(t, expectedBlockSize, blockSize, "block size calculation incorrect") {
			t.FailNow()
		}
	}
	err := switchPath.BuildBlocks()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate path traversal with continuous block changes.
	t.Logf("fwd block: %+v\n", switchPath.ForwardBlock)
	block := slices.Clone[[]byte, byte](switchPath.ForwardBlock)
	wastedBytes := len(block)
	for i := 0; ; i++ {
		nextHop, err := NextRotateSwitchBlock(block, switchPath.Hops[i].ReturnLabel)
		if err != nil {
			t.Fatal(err)
		}
		// Count zeros from back to check for wasted bytes.
		for i := 0; i < len(block); i++ {
			if block[len(block)-1-i] != 0 {
				if i < wastedBytes {
					wastedBytes = i
				}
				break
			}
		}

		// Exit loop when destination reached.
		if nextHop == 0 {
			break
		}
		t.Logf("hop block: %+v\n", block)
	}
	TransformToReturnBlock(block)
	t.Logf("ret block: %+v\n", block)
	if !assert.Equalf(t, switchPath.ReturnBlock, block, "block rotation failed, return block mismatches") {
		t.FailNow()
	}

	// Simulate return path traversal with continuous block changes.
	for i := len(switchPath.Hops) - 1; ; i-- {
		nextHop, err := NextRotateSwitchBlock(block, switchPath.Hops[i].ForwardLabel)
		if err != nil {
			t.Fatal(err)
		}
		// Count zeros from back to check for wasted bytes.
		for i := 0; i < len(block); i++ {
			if block[len(block)-1-i] != 0 {
				if i < wastedBytes {
					wastedBytes = i
				}
				break
			}
		}

		// Exit loop when destination reached.
		if nextHop == 0 {
			break
		}
		t.Logf("hop block: %+v\n", block)
	}
	TransformToReturnBlock(block)
	t.Logf("fin block: %+v\n", block)
	if !assert.Equalf(t, switchPath.ForwardBlock, block, "block rotation failed, forward block mismatches") {
		t.FailNow()
	}
	if wastedBytes > 0 {
		t.Fatalf("block size too big, wasted %d bytes", wastedBytes)
	}
}

func formatSwitchPath(switchPath *SwitchPath) string {
	fwd := make([]string, len(switchPath.Hops))
	ret := make([]string, len(switchPath.Hops))

	for i := 0; i < len(switchPath.Hops); i++ {
		fwd[i] = strconv.Itoa(int(switchPath.Hops[i].ForwardLabel))
		ret[i] = strconv.Itoa(int(switchPath.Hops[len(switchPath.Hops)-i-1].ReturnLabel))
	}

	return fmt.Sprintf(
		"fwd:%s ret:%s",
		strings.Join(fwd, "-"),
		strings.Join(ret, "-"),
	)
}

func TestDeriveSwitchLabelFromIP(t *testing.T) {
	t.Parallel()

	// Routable
	testDeriveLabel(t, "fd64:74af:da5:170c:f93d:dba:2261:bb5", 53)
	testDeriveLabel(t, "fd5c:721e:c7d1:27a0:dd1:5924:24b9:f60b", 11)
	testDeriveLabel(t, "fd59:8122:fe41:aec:faeb:c9b9:1459:716a", 106)
	// Private
	testDeriveLabel(t, "fdfb:9f02:180c:eeb5:e133:e9e1:23c0:2b5d", 11101)
	testDeriveLabel(t, "fdc0:9c48:9402:8633:d611:c4de:bdb3:5f3c", 7996)
	testDeriveLabel(t, "fdd5:6d1:72fb:7f17:6e5c:a1e9:1096:34c9", 13513)

	// Test failing derivation
	testDeriveLabel(t, "fd4e:4aae:7bf3:d4af:c07:5f2d:24f8:ef00", 0)
	testDeriveLabel(t, "fd0b:c5c5:b4da:a9be:83d3:b3fd:52d5:8f80", 0)
	testDeriveLabel(t, "fdd2:c951:6aaa:28c:8bce:815b:6f6d:0000", 0)
	testDeriveLabel(t, "fd9e:f1f1:1881:506e:d30f:d8f5:7efe:c000", 0)
}

func testDeriveLabel(t *testing.T, ip string, expectedLabel SwitchLabel) {
	t.Helper()

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatal(err)
	}
	label, ok := DeriveSwitchLabelFromIP(addr)
	switch {
	case expectedLabel == 0 && !ok:
		// Expected to not be able derive.
	case expectedLabel == 0 && ok:
		t.Errorf("expected that label cannot derived from address %s", addr)
	case !ok:
		t.Errorf("expected label can be derived from address %s", addr)
	default:
		assert.Equalf(t, expectedLabel, label, "derived label does not match expected label for %s", addr)
	}
}
