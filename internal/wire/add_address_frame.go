package wire

import (
	"bytes"
	"errors"
	"net"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var (
	ErrUnknownIPVersion = errors.New("AddAddressFrame: unknown IP version")
)

var (
	errInconsistentAddrIPVersion = errors.New("internal inconsistency: Addr does not match IP version")
)

// A AddAddressFrame in QUIC
type AddAddressFrame struct {
	IPVersion uint8
	Addr      net.UDPAddr
}

func (f *AddAddressFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	typeByte := uint8(0x10)
	b.WriteByte(typeByte)
	b.WriteByte(f.IPVersion)

	switch f.IPVersion {
	case 4:
		ip := f.Addr.IP.To4()
		if ip == nil {
			return errInconsistentAddrIPVersion
		}
		for i := 0; i < 4; i++ {
			b.WriteByte(ip[i])
		}
	case 6:
		ip := f.Addr.IP.To16()
		if ip == nil {
			return errInconsistentAddrIPVersion
		}
		for i := 0; i < 16; i++ {
			b.WriteByte(ip[i])
		}
	default:
		return ErrUnknownIPVersion
	}

	utils.GetByteOrder(version).WriteUint16(b, uint16(f.Addr.Port))

	return nil
}

func ParseAddAddressFrame(r *bytes.Reader, version protocol.VersionNumber) (*AddAddressFrame, error) {
	frame := &AddAddressFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		 return nil, err
	}

	ipv, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	frame.IPVersion = ipv

	switch frame.IPVersion {
	case 4:
		a, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		d, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		frame.Addr.IP = net.IPv4(a, b, c, d)
	case 6:
		ip := make([]byte, 16)
		for i := 0; i < net.IPv6len; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			ip[i] = b
		}
		frame.Addr.IP = net.IP(ip)

	default:
		return nil, ErrUnknownIPVersion
	}

	port, err := utils.GetByteOrder(version).ReadUint16(r)
	if err != nil {
		return nil, err
	}

	frame.Addr.Port = int(port)

	return frame, nil
}

func (f* AddAddressFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	switch f.IPVersion {
	case 4:
		return 1 + 1 + 4 + 2, nil
	case 6:
		return 1 + 1 + 16 + 2, nil
	default:
		return 0, ErrUnknownIPVersion
	}
}
