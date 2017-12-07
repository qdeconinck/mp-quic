package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const (
	minPathTimer = 10 * time.Millisecond
	// XXX (QDC): To avoid idling...
	maxPathTimer = 1 * time.Second
)

type path struct {
	pathID protocol.PathID
	conn   connection
	sess   *session

	rttStats *congestion.RTTStats

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler

	open      utils.AtomicBool
	closeChan chan *qerr.QuicError
	runClosed chan struct{}

	potentiallyFailed utils.AtomicBool

	sentPacket          chan struct{}

	// It is now the responsibility of the path to keep its packet number
	packetNumberGenerator *packetNumberGenerator

	lastRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	leastUnacked protocol.PacketNumber

	lastNetworkActivityTime time.Time

	timer           *utils.Timer
}

// setup initializes values that are independent of the perspective
func (p *path) setup(oliaSenders map[protocol.PathID]*congestion.OliaSender) {
	p.rttStats = &congestion.RTTStats{}

	var cong congestion.SendAlgorithm

	if p.sess.version >= protocol.VersionMP && oliaSenders != nil && p.pathID != protocol.InitialPathID {
		cong = congestion.NewOliaSender(oliaSenders, p.rttStats, protocol.InitialCongestionWindow, protocol.DefaultMaxCongestionWindow)
		oliaSenders[p.pathID] = cong.(*congestion.OliaSender)
	}

	sentPacketHandler := ackhandler.NewSentPacketHandler(p.rttStats, cong, p.onRTO)

	now := time.Now()

	p.sentPacketHandler = sentPacketHandler
	p.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(p.sess.version)

	p.packetNumberGenerator = newPacketNumberGenerator(protocol.SkipPacketAveragePeriodLength)

	p.closeChan = make(chan *qerr.QuicError, 1)
	p.runClosed = make(chan struct{}, 1)
	p.sentPacket = make(chan struct{}, 1)

	p.timer = utils.NewTimer()
	p.lastNetworkActivityTime = now

	p.open.Set(true)
	p.potentiallyFailed.Set(false)

	// Once the path is setup, run it
	go p.run()
}

func (p *path) close() error {
	p.open.Set(false)
	return nil
}

func (p *path) run() {
	// XXX (QDC): relay everything to the session, maybe not the most efficient
runLoop:
	for {
		// Close immediately if requested
		select {
		case <-p.closeChan:
			break runLoop
		default:
		}

		p.maybeResetTimer()

		select {
		case <-p.closeChan:
			break runLoop
		case <-p.timer.Chan():
			p.timer.SetRead()
			select {
			case p.sess.pathTimers <- p:
			// XXX (QDC): don't remain stuck here!
			case <-p.closeChan:
				break runLoop
			case <-p.sentPacket:
				// Don't remain stuck here!
			}
		case <-p.sentPacket:
			// Used to reset the path timer
		}
	}
	p.close()
	p.runClosed <- struct{}{}
}

func (p *path) SendingAllowed() bool {
	return p.open.Get() && p.sentPacketHandler.SendingAllowed()
}

func (p *path) GetStopWaitingFrame(force bool) *wire.StopWaitingFrame {
	return p.sentPacketHandler.GetStopWaitingFrame(force)
}

func (p *path) GetAckFrame() *wire.AckFrame {
	ack := p.receivedPacketHandler.GetAckFrame()
	if ack != nil {
		ack.PathID = p.pathID
	}

	return ack
}

func (p *path) GetClosePathFrame() *wire.ClosePathFrame {
	closePathFrame := p.receivedPacketHandler.GetClosePathFrame()
	if closePathFrame != nil {
		closePathFrame.PathID = p.pathID
	}

	return closePathFrame
}

func (p *path) maybeResetTimer() {
	deadline := p.lastNetworkActivityTime.Add(p.idleTimeout())

	if ackAlarm := p.receivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		deadline = ackAlarm
	}
	if lossTime := p.sentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		deadline = utils.MinTime(deadline, lossTime)
	}

	deadline = utils.MinTime(utils.MaxTime(deadline, time.Now().Add(minPathTimer)), time.Now().Add(maxPathTimer))

	p.timer.Reset(deadline)
}

func (p *path) idleTimeout() time.Duration {
	// TODO (QDC): probably this should be refined at path level
	cryptoSetup := p.sess.cryptoSetup
	if cryptoSetup != nil {
		if p.open.Get() && (p.pathID != 0 || p.sess.handshakeComplete) {
			return p.sess.connectionParameters.GetIdleConnectionStateLifetime()
		}
		return p.sess.config.HandshakeTimeout
	}
	return time.Second
}

func (p *path) handlePacketImpl(pkt *receivedPacket) error {
	if !p.open.Get() {
		// Path is closed, ignore packet
		return nil
	}

	if !pkt.rcvTime.IsZero() {
		p.lastNetworkActivityTime = pkt.rcvTime
	}
	hdr := pkt.publicHeader
	data := pkt.data

	// We just received a new packet on that path, so it works
	p.potentiallyFailed.Set(false)

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		p.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	packet, err := p.sess.unpacker.Unpack(hdr.Raw, hdr, data)
	if utils.Debug() {
		if err != nil {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.pathID)
		} else {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x, %s", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.pathID, packet.encryptionLevel)
		}
	}

	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return err
	}
	if p.sess.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		p.conn.SetCurrentRemoteAddr(pkt.remoteAddr)
	}
	if err != nil {
		return err
	}

	p.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrupting, so we are sure the packet is not attacker-controlled
	p.largestRcvdPacketNumber = utils.MaxPacketNumber(p.largestRcvdPacketNumber, hdr.PacketNumber)

	isRetransmittable := ackhandler.HasRetransmittableFrames(packet.frames)
	if err = p.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, isRetransmittable); err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return p.sess.handleFrames(packet.frames, p)
}

func (p *path) onRTO(lastSentTime time.Time) bool {
	// Was there any activity since last sent packet?
	if p.lastNetworkActivityTime.Before(lastSentTime) {
		p.potentiallyFailed.Set(true)
		p.sess.schedulePathsFrame()
		return true
	}
	return false
}

func (p *path) SetLeastUnacked(leastUnacked protocol.PacketNumber) {
	p.leastUnacked = leastUnacked
}
