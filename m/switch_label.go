package m

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
)

// Max Switch Label Sizes.
const (
	MaxRoutableSwitchLabel = 127   // Fits into 1 byte varint
	MaxPrivateSwitchLabel  = 16383 // Fits into 2 byte varint

	MinHopDelay = 5 // In milliseconds.
)

// Switch Label Errors.
var (
	ErrBufTooSmall = errors.New("varint: buf too small")
	ErrValueTooBig = errors.New("varint: value too big")
)

// SwitchPath describes a path through the network using switch labels.
type SwitchPath struct {
	Hops         []SwitchHop `json:"hops,omitempty"         yaml:"hops,omitempty"`
	ForwardBlock []byte      `json:"forwardBlock,omitempty" yaml:"forwardBlock,omitempty"`
	ReturnBlock  []byte      `json:"returnBlock,omitempty"  yaml:"returnBlock,omitempty"`

	TotalDelay uint16 `json:"totalDelay,omitempty" yaml:"totalDelay,omitempty"` // In milliseconds.
	TotalHops  uint8  `json:"totalHops,omitempty"  yaml:"totalHops,omitempty"`
}

// SwitchHop descibes a single hop in a path.
type SwitchHop struct {
	Router       netip.Addr  `json:"router,omitempty"       yaml:"router,omitempty"`
	Delay        uint16      `json:"delay,omitempty"        yaml:"delay,omitempty"` // In milliseconds.
	ForwardLabel SwitchLabel `json:"forwardLabel,omitempty" yaml:"forwardLabel,omitempty"`
	ReturnLabel  SwitchLabel `json:"returnLabel,omitempty"  yaml:"returnLabel,omitempty"`
}

// SwitchLabel is used to identify an interface on a router.
type SwitchLabel uint16

// NextRotateSwitchBlock extracts the next switch label and rotates the block
// so it can be reversed by the destination.
func NextRotateSwitchBlock(block []byte, returnLabel SwitchLabel) (nextHop SwitchLabel, err error) {
	// Read next hop varint switch label.
	next, bytesRead := binary.Uvarint(block)
	if bytesRead <= 0 {
		if bytesRead == 0 {
			return 0, ErrBufTooSmall
		}
		return 0, ErrValueTooBig
	}

	// Move data to front, clear the rest.
	n := copy(block, block[bytesRead:])
	clear(block[n:])

	// Search for the second zero, this is where the return label needs to be put.
	var (
		seenFirstZero    = next == 0      // If the next hop is zero, this counts as a seen zero.
		returnLabelStart = len(block) - 1 // Default is last byte.
	)
blockScan:
	for i := 0; i < len(block); i++ {
		switch {
		case block[i] != 0:
			// continue
		case !seenFirstZero:
			seenFirstZero = true
		default:
			returnLabelStart = i
			break blockScan
		}
	}

	// Add return label at correct position and reverse it.
	labelSlot := block[returnLabelStart : returnLabelStart+returnLabel.EncodedSize()]
	binary.PutUvarint(labelSlot, uint64(returnLabel))
	slices.Reverse[[]byte, byte](labelSlot)

	if returnLabel > 0 {
		for i := 0; i < len(labelSlot); i++ {
			if labelSlot[i] == 0 {
				panic(returnLabel)
			}
		}
	}

	// fmt.Printf("new block: %+v\n", block)

	return SwitchLabel(next), nil
}

// TransformToReturnBlock transform the given block to a return block that
// takes the exact route it came from.
func TransformToReturnBlock(block []byte) {
	// Reverse the full slice.
	slices.Reverse[[]byte, byte](block)
	// Pull data to front to remove leading zeros.
	for i := 0; i < len(block); i++ {
		if block[i] != 0 {
			if i > 0 {
				n := copy(block, block[i:])
				clear(block[n:])
			}
			break
		}
	}
}

// BuildBlocks builds the forward and return switch label blocks from the path.
func (sp *SwitchPath) BuildBlocks() error {
	// Check for single hop switch path.
	if len(sp.Hops) == 0 {
		sp.ForwardBlock = []byte{0}
		sp.ReturnBlock = []byte{0}
		return nil
	}

	blockSize, err := sp.CalculateBlockSize()
	if err != nil {
		return err
	}

	sp.ForwardBlock = make([]byte, blockSize)
	var index int
	for i := 0; i < len(sp.Hops)-1; i++ {
		written := binary.PutUvarint(
			sp.ForwardBlock[index:],
			uint64(sp.Hops[i].ForwardLabel),
		)
		index += written
	}

	sp.ReturnBlock = make([]byte, blockSize)
	index = 0
	for i := len(sp.Hops) - 1; i > 0; i-- {
		written := binary.PutUvarint(
			sp.ReturnBlock[index:],
			uint64(sp.Hops[i].ReturnLabel),
		)
		index += written
	}

	return nil
}

// EncodedSize returns the number of bytes needed to encode the switch label.
func (sl SwitchLabel) EncodedSize() int {
	switch {
	case sl <= MaxRoutableSwitchLabel:
		return 1
	case sl <= MaxPrivateSwitchLabel:
		return 2
	default:
		return 3
	}
}

// CalculateBlockSize calculates the maximum needed block size in the whole path.
func (sp *SwitchPath) CalculateBlockSize() (int, error) {
	// Check for single hop switch path.
	if len(sp.Hops) == 0 {
		return 0, nil
	}

	// Check if the mandatory 0 labels are in the right spots.
	if sp.Hops[0].ReturnLabel != 0 ||
		sp.Hops[len(sp.Hops)-1].ForwardLabel != 0 {
		return 0, errors.New("invalid switch path")
	}

	// Build label simulation with encoded sizes.
	var size uint8
	// Size simulation contains both hop paths in the order they are added,
	// but the zero label in the center overlaps!
	sizeSim := make([]uint8, len(sp.Hops)*2-1)
	for i := 0; i < len(sp.Hops); i++ {
		sizeSim[i] = uint8(sp.Hops[i].ForwardLabel.EncodedSize())
		sizeSim[len(sp.Hops)+i-1] = uint8(sp.Hops[i].ReturnLabel.EncodedSize())
	}
	// Now, simulate the label rotation and check every rotation for the required size.
	// Labels are always one element shorter than the path.
	for i := 0; i <= len(sp.Hops); i++ {
		var caseSize uint8
		for j := i; j < i+len(sp.Hops)-1; j++ {
			caseSize += sizeSim[j]
		}
		if caseSize > size {
			size = caseSize
		}
	}
	// fmt.Println(sizeSim)
	return int(size), nil

	// Failed Alternative 1:
	// Count encoded size of both all forward and return labels separately, use bigger of the two.
	//
	// var fw, ret int
	// for _, hop := range sp.Hops {
	// 	fw += hop.ForwardLabel.EncodedSize()
	// 	ret += hop.ReturnLabel.EncodedSize()
	// }
	// // Remove one, as start switch return label and destination switch forward
	// // label are always both zero and can be shared.
	// fw -= 1
	// ret -= 1

	// Failed Alternative 2:
	// Count encoded size using the bigger of the opposite labels.
	//
	// var size int
	// for i := 0; i < len(sp.Hops); i++ {
	// 	size += max(
	// 		sp.Hops[i].ForwardLabel.EncodedSize(),
	// 		sp.Hops[i].ReturnLabel.EncodedSize(),
	// 	)
	// }
	// size -= 1
}

// CalculateTotals calculates the total values of the switch path.
func (sp *SwitchPath) CalculateTotals() {
	// Calculate the total actual hops.
	switch len(sp.Hops) {
	case 0, 1:
		// TODO: 0, 1 is invalid
		sp.TotalHops = 1
	default:
		if len(sp.Hops)-1 <= 255 {
			sp.TotalHops = uint8(len(sp.Hops) - 1)
		} else {
			// TotalHops is used for route selection and cleaning,
			// an inaccurate value won't break the system too much.
			sp.TotalHops = 255
		}
	}

	// Calculate the total delay.
	var delay uint
	for _, hop := range sp.Hops {
		if hop.Delay < MinHopDelay {
			// Add the minimum hop delay, if below.
			delay += MinHopDelay
		} else {
			delay += uint(hop.Delay)
		}
	}
	switch {
	case delay == 0:
		// Do not reset existing TotalDelay, in order for to be able use the existing value.
	case delay <= 65535:
		sp.TotalDelay = uint16(delay)
	default:
		// TotalDelay is used for route selection and cleaning,
		// an inaccurate value won't break the system too much.
		sp.TotalDelay = 65535
	}
}

// DeriveSwitchLabelFromIP derives a switch label from the given IP and reports
// whether it was able to do so.
func DeriveSwitchLabelFromIP(ip netip.Addr) (label SwitchLabel, ok bool) {
	ipData := ip.As16()

	// Create two byte label for private addresses.
	if PrivacyAddressPrefix.Contains(ip) {
		label = SwitchLabel(beUint16(ipData[len(ipData)-2:])) & MaxPrivateSwitchLabel
		if label == 0 || label <= MaxRoutableSwitchLabel {
			return 0, false
		}
		return label, true
	}

	// Create single byte label for routable addresses.
	label = SwitchLabel(ipData[len(ipData)-1]) & MaxRoutableSwitchLabel
	if label == 0 {
		return 0, false
	}
	return label, true
}

// GetRandomSwitchLabel generate a random switch label.
func GetRandomSwitchLabel(forRoutableAddress bool) (label SwitchLabel, ok bool) {
	// Get two bytes of random data.
	var r [2]byte
	_, err := rand.Read(r[:])
	if err != nil {
		return 0, false
	}

	// Create two byte label for private addresses.
	if !forRoutableAddress {
		label = SwitchLabel(beUint16(r[:])) & MaxPrivateSwitchLabel
		if label == 0 || label <= MaxRoutableSwitchLabel {
			return 0, false
		}
		return label, true
	}

	// Create single byte label for routable addresses.
	label = SwitchLabel(r[0]) & MaxRoutableSwitchLabel
	if label == 0 {
		return 0, false
	}
	return label, true
}

func beUint16(b []byte) uint16 {
	return uint16(b[1]) | uint16(b[0])<<8
}
