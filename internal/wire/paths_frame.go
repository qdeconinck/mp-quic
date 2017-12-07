package wire

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var (
	ErrTooManyPaths = errors.New("PathsFrame: more paths than the maximum enabled")
	ErrPathsNumber = errors.New("PathsFrame: number of paths advertised and # of paths do not match")
	ErrMissingRTT = errors.New("PathsFrame: number of paths IDs and number of remote RTTs do not match")
)

// A PathsFrame in QUIC
type PathsFrame struct {
	MaxNumPaths uint8
	NumPaths    uint8
	PathIDs     []protocol.PathID
	RemoteRTTs  []time.Duration
}

func (f *PathsFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	typeByte := uint8(0x12)
	b.WriteByte(typeByte)
	b.WriteByte(f.MaxNumPaths)
	b.WriteByte(f.NumPaths)

	if int(f.NumPaths) != len(f.PathIDs) {
		return ErrPathsNumber
	}

	if len(f.PathIDs) != len(f.RemoteRTTs) {
		return ErrMissingRTT
	}

	for i := 0; i < len(f.PathIDs); i++ {
		b.WriteByte(uint8(f.PathIDs[i]))
		utils.GetByteOrder(version).WriteUfloat16(b, uint64(f.RemoteRTTs[i]/time.Microsecond))
	}

	return nil
}

func ParsePathsFrame(r *bytes.Reader, version protocol.VersionNumber) (*PathsFrame, error) {
	frame := &PathsFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	maxNum, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	frame.MaxNumPaths = maxNum

	num, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	frame.NumPaths = num
	if frame.NumPaths > frame.MaxNumPaths {
		return nil, ErrTooManyPaths
	}

	for i := 0; i < int(frame.NumPaths); i++ {
		pathID, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		frame.PathIDs = append(frame.PathIDs, protocol.PathID(pathID))
		remoteRTT, err := utils.GetByteOrder(version).ReadUfloat16(r)
		if err != nil {
			return nil, err
		}
		frame.RemoteRTTs = append(frame.RemoteRTTs, time.Duration(remoteRTT) * time.Microsecond)
	}

	return frame, nil
}

func (f *PathsFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	length := 1 + 1 + 1 + (3 * f.NumPaths)
	return protocol.ByteCount(length), nil
}
