package congestion

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

const scale uint = 10

// Olia implements the olia algorithm from MPTCP
type Olia struct {
	// Total number of bytes acked two losses ago
	loss1 protocol.ByteCount
	// Total number of bytes acked at the last loss
	loss2 protocol.ByteCount
	// Current number of bytes acked
	loss3 protocol.ByteCount
	epsilonNum int
	epsilonDen uint32
	sndCwndCnt int
	// We need to keep a reference to all paths
}

func NewOlia(ackedBytes protocol.ByteCount) *Olia {
	o := &Olia{
		loss1:      ackedBytes,
		loss2:      ackedBytes,
		loss3:      ackedBytes,
		epsilonNum: 0,
		epsilonDen: 1,
		sndCwndCnt: 0,
	}
	return o
}

func oliaScale(val uint64, scale uint) uint64 {
	return uint64(val) << scale
}

func (o *Olia) Reset() {
	o.loss1 = 0
	o.loss2 = 0
	o.loss3 = 0
	o.epsilonNum = 0
	o.epsilonDen = 1
	o.sndCwndCnt = 0
}

func (o *Olia) SmoothedBytesBetweenLosses() protocol.ByteCount {
	return utils.MaxByteCount(o.loss3 - o.loss2, o.loss2 - o.loss1)
}

func (o *Olia) UpdateAckedSinceLastLoss(ackedBytes protocol.ByteCount) {
	o.loss3 += ackedBytes
}

func (o *Olia) OnPacketLost() {
	// TODO should we add so many if check? Not done here
	o.loss1 = o.loss2
	o.loss2 = o.loss3
}

func (o *Olia) CongestionWindowAfterAck(currentCongestionWindow protocol.PacketNumber, rate protocol.ByteCount, cwndScaled uint64) protocol.PacketNumber {
	newCongestionWindow := currentCongestionWindow
	incDen := uint64(o.epsilonDen) * uint64(currentCongestionWindow) * uint64(rate)
	if incDen == 0 {
		incDen = 1
	}

	// calculate the increasing term, scaling is used to reduce the rounding effect
	if o.epsilonNum == -1 {
		if uint64(o.epsilonDen) * cwndScaled * cwndScaled < uint64(rate) {
			incNum := uint64(rate) - uint64(o.epsilonDen) * cwndScaled * cwndScaled
			o.sndCwndCnt -= int(oliaScale(incNum, scale) / uint64(incDen))
		} else {
			incNum := uint64(o.epsilonDen) * cwndScaled * cwndScaled - uint64(rate)
			o.sndCwndCnt += int(oliaScale(incNum, scale) / uint64(incDen))
		}
	} else {
		incNum := uint64(o.epsilonNum) * uint64(rate) + uint64(o.epsilonDen) * cwndScaled * cwndScaled
		o.sndCwndCnt += int(oliaScale(incNum, scale) / uint64(incDen))
	}

	if o.sndCwndCnt >= (1 << scale) - 1 {
		newCongestionWindow++
		o.sndCwndCnt = 0
	} else if o.sndCwndCnt <= 0 - (1 << scale) + 1 {
		newCongestionWindow = utils.MaxPacketNumber(1, currentCongestionWindow - 1)
		o.sndCwndCnt = 0
	}
	return newCongestionWindow
}
