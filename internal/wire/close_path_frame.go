package wire

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A ClosePathFrame in (IETF) QUIC
type ClosePathFrame struct {
	PathID       protocol.PathID
	LargestAcked protocol.PacketNumber
	LowestAcked  protocol.PacketNumber
	AckRanges    []AckRange // has to be ordered. The ACK range with the highest First goes first, the ACK range with the lowest First goes last
}

func (f *ClosePathFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	typeByte := uint8(0x11)
	b.WriteByte(typeByte)

	b.WriteByte(uint8(f.PathID))

	largestAckedLen := protocol.GetPacketNumberLength(f.LargestAcked)
	var flags uint8 = 0x00

	if f.HasMissingRanges() {
		flags |= 0x10
	}

	if largestAckedLen != protocol.PacketNumberLen1 {
		flags ^= (uint8(largestAckedLen / 2)) << 2
	}

	missingSequenceNumberDeltaLen := f.getMissingSequenceNumberDeltaLen()
	if missingSequenceNumberDeltaLen != protocol.PacketNumberLen1 {
		flags ^= (uint8(missingSequenceNumberDeltaLen / 2))
	}

	b.WriteByte(flags)

	var numRanges uint64
	var numRangesWritten uint64
	if f.HasMissingRanges() {
		numRanges = f.numWritableNackRanges()
		if numRanges > 0xFF {
			panic("ClosePathFrame: Too many ACK ranges")
		}
		b.WriteByte(uint8(numRanges - 1))
	}

	switch largestAckedLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(f.LargestAcked))
	case protocol.PacketNumberLen2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(f.LargestAcked))
	case protocol.PacketNumberLen4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(f.LargestAcked))
	case protocol.PacketNumberLen6:
		utils.GetByteOrder(version).WriteUint48(b, uint64(f.LargestAcked))
	}

	var firstAckBlockLength protocol.PacketNumber
	if !f.HasMissingRanges() {
		firstAckBlockLength = f.LargestAcked - f.LowestAcked + 1
	} else {
		if f.LargestAcked != f.AckRanges[0].Last {
			return errInconsistentAckLargestAcked
		}
		if f.LowestAcked != f.AckRanges[len(f.AckRanges)-1].First {
			return errInconsistentAckLowestAcked
		}
		firstAckBlockLength = f.LargestAcked - f.AckRanges[0].First + 1
		numRangesWritten++
	}

	switch missingSequenceNumberDeltaLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(firstAckBlockLength))
	case protocol.PacketNumberLen2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(firstAckBlockLength))
	case protocol.PacketNumberLen4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(firstAckBlockLength))
	case protocol.PacketNumberLen6:
		utils.GetByteOrder(version).WriteUint48(b, uint64(firstAckBlockLength))
	}

	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}

		length := ackRange.Last - ackRange.First + 1
		gap := f.AckRanges[i-1].First - ackRange.Last - 1

		num := gap/0xFF + 1
		if gap%0xFF == 0 {
			num--
		}

		if num == 1 {
			b.WriteByte(uint8(gap))
			switch missingSequenceNumberDeltaLen {
			case protocol.PacketNumberLen1:
				b.WriteByte(uint8(length))
			case protocol.PacketNumberLen2:
				utils.GetByteOrder(version).WriteUint16(b, uint16(length))
			case protocol.PacketNumberLen4:
				utils.GetByteOrder(version).WriteUint32(b, uint32(length))
			case protocol.PacketNumberLen6:
				utils.GetByteOrder(version).WriteUint48(b, uint64(length))
			}
			numRangesWritten++
		} else {
			for i := 0; i < int(num); i++ {
				var lengthWritten uint64
				var gapWritten uint8

				if i == int(num)-1 { // last block
					lengthWritten = uint64(length)
					gapWritten = uint8(1 + ((gap - 1) % 255))
				} else {
					lengthWritten = 0
					gapWritten = 0xFF
				}

				b.WriteByte(gapWritten)
				switch missingSequenceNumberDeltaLen {
				case protocol.PacketNumberLen1:
					b.WriteByte(uint8(lengthWritten))
				case protocol.PacketNumberLen2:
					utils.GetByteOrder(version).WriteUint16(b, uint16(lengthWritten))
				case protocol.PacketNumberLen4:
					utils.GetByteOrder(version).WriteUint32(b, uint32(lengthWritten))
				case protocol.PacketNumberLen6:
					utils.GetByteOrder(version).WriteUint48(b, lengthWritten)
				}

				numRangesWritten++
			}
		}

		// this is needed if not all AckRanges can be written to the ACK frame (if there are more than 0xFF)
		if numRangesWritten >= numRanges {
			break
		}
	}

	if numRanges != numRangesWritten {
		return errors.New("BUG: Inconsistent number of ACK ranges written in ClosePath")
	}

	return nil
}

func ParseClosePathFrame(r *bytes.Reader, version protocol.VersionNumber) (*ClosePathFrame, error) {
	frame := &ClosePathFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	pathID, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	frame.PathID = protocol.PathID(pathID)

	flags, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	hasMissingRanges := false
	if flags&0x10 == 0x10 {
		hasMissingRanges = true
	}

	largestAckedLen := 2 * ((flags & 0x0C) >> 2)
	if largestAckedLen == 0 {
		largestAckedLen = 1
	}

	missingSequenceNumberDeltaLen := 2 * (flags & 0x03)
	if missingSequenceNumberDeltaLen == 0 {
		missingSequenceNumberDeltaLen = 1
	}

	var numAckBlocks uint8
	if hasMissingRanges {
		numAckBlocks, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if hasMissingRanges && numAckBlocks == 0 {
		return nil, ErrInvalidAckRanges
	}

	largestAcked, err := utils.GetByteOrder(version).ReadUintN(r, largestAckedLen)
	if err != nil {
		return nil, err
	}
	frame.LargestAcked = protocol.PacketNumber(largestAcked)

	ackBlockLength, err := utils.GetByteOrder(version).ReadUintN(r, missingSequenceNumberDeltaLen)
	if err != nil {
		return nil, err
	}
	if frame.LargestAcked > 0 && ackBlockLength < 1 {
		return nil, ErrInvalidFirstAckRange
	}

	if ackBlockLength > largestAcked {
		return nil, ErrInvalidAckRanges
	}

	if hasMissingRanges {
		ackRange := AckRange{
			First: protocol.PacketNumber(largestAcked-ackBlockLength) + 1,
			Last:  frame.LargestAcked,
		}
		frame.AckRanges = append(frame.AckRanges, ackRange)

		var inLongBlock bool
		var lastRangeComplete bool
		for i := uint8(0); i < numAckBlocks; i++ {
			var gap uint8
			gap, err = r.ReadByte()
			if err != nil {
				return nil, err
			}

			ackBlockLength, err = utils.GetByteOrder(version).ReadUintN(r, missingSequenceNumberDeltaLen)
			if err != nil {
				return nil, err
			}

			length := protocol.PacketNumber(ackBlockLength)

			if inLongBlock {
				frame.AckRanges[len(frame.AckRanges)-1].First -= protocol.PacketNumber(gap) + length
				frame.AckRanges[len(frame.AckRanges)-1].Last -= protocol.PacketNumber(gap)
			} else {
				lastRangeComplete = false
				ackRange := AckRange{
					Last: frame.AckRanges[len(frame.AckRanges)-1].First - protocol.PacketNumber(gap) - 1,
				}
				ackRange.First = ackRange.Last - length + 1
				frame.AckRanges = append(frame.AckRanges, ackRange)
			}

			if length > 0 {
				lastRangeComplete = true
			}

			inLongBlock = (ackBlockLength == 0)
		}

		// if the last range was not complete, First and Last make no sense
		// remote the range from frame.AckRanges
		if !lastRangeComplete {
			frame.AckRanges = frame.AckRanges[:len(frame.AckRanges)-1]
		}

		frame.LowestAcked = frame.AckRanges[len(frame.AckRanges)-1].First
	} else {
		if frame.LargestAcked == 0 {
			frame.LowestAcked = 0
		} else {
			frame.LowestAcked = protocol.PacketNumber(largestAcked + 1 - ackBlockLength)
		}
	}

	if !frame.validateAckRanges() {
		return nil, ErrInvalidAckRanges
	}

	return frame, nil
}

func (f *ClosePathFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	length := protocol.ByteCount(1 + 1 + 1) // 1 TypeByte, 1 PathID, 1 Flags
	length += protocol.ByteCount(protocol.GetPacketNumberLength(f.LargestAcked))

	missingSequenceNumberDeltaLen := protocol.ByteCount(f.getMissingSequenceNumberDeltaLen())

	if f.HasMissingRanges() {
		// The First ACK block and the NumBlocks field are taken into account
		length += (1 + missingSequenceNumberDeltaLen) * protocol.ByteCount(f.numWritableNackRanges())
	} else {
		length += missingSequenceNumberDeltaLen
	}

	return length, nil
}

func (f *ClosePathFrame) HasMissingRanges() bool {
	return len(f.AckRanges) > 0
}

func (f *ClosePathFrame) validateAckRanges() bool {
	if len(f.AckRanges) == 0 {
		return true
	}

	// if there are missing packets, there will always be at least 2 ACK ranges
	if len(f.AckRanges) == 1 {
		return false
	}

	if f.AckRanges[0].Last != f.LargestAcked {
		return false
	}

	// check the validity of every single ACK range
	for _, ackRange := range f.AckRanges {
		if ackRange.First > ackRange.Last {
			return false
		}
	}

	// check the consistency for ACK with multiple NACK ranges
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}
		lastAckRange := f.AckRanges[i-1]
		if lastAckRange.First <= ackRange.First {
			return false
		}
		if lastAckRange.First <= ackRange.Last+1 {
			return false
		}
	}

	return true
}

func (f *ClosePathFrame) getMissingSequenceNumberDeltaLen() protocol.PacketNumberLen {
	var maxRangeLength protocol.PacketNumber

	if f.HasMissingRanges() {
		for _, ackRange := range f.AckRanges {
			rangeLength := ackRange.Last - ackRange.First + 1
			if rangeLength > maxRangeLength {
				maxRangeLength = rangeLength
			}
		}
	} else {
		maxRangeLength = f.LargestAcked - f.LowestAcked + 1
	}

	if maxRangeLength <= 0xFF {
		return protocol.PacketNumberLen1
	}
	if maxRangeLength <= 0xFFFF {
		return protocol.PacketNumberLen2
	}
	if maxRangeLength <= 0xFFFFFFFF {
		return protocol.PacketNumberLen4
	}

	return protocol.PacketNumberLen6
}

// numWritableNackRanges calculates the number of ACK blocks tht are about to be written
// this number is different from len(f.AckRanges) for the case of long gaps (> 255 packets)
func (f *ClosePathFrame) numWritableNackRanges() uint64 {
	if len(f.AckRanges) == 0 {
		return 0
	}

	var numRanges uint64
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}

		lastAckRange := f.AckRanges[i-1]
		gap := lastAckRange.First - ackRange.Last - 1
		rangeLength := 1 + uint64(gap)/0xFF
		if uint64(gap)%0xFF == 0 {
			rangeLength--
		}

		if numRanges+rangeLength < 0xFF {
			numRanges += rangeLength
		} else {
			break
		}
	}

	return numRanges + 1
}

// AcksPacket determines if this ClosePath frame acks a certain packet number
func (f *ClosePathFrame) AcksPacket(p protocol.PacketNumber) bool {
	if p < f.LowestAcked || p > f.LargestAcked { // this is just a performance optimization
		return false
	}

	if f.HasMissingRanges() {
		// TODO: this could be implemented as a binary search
		for _, ackRange := range f.AckRanges {
			if p >= ackRange.First && p <= ackRange.Last {
				return true
			}
		}
		return false
	}
	// if packet doesn't have missing ranges
	return (p >= f.LowestAcked && p <= f.LargestAcked)
}
