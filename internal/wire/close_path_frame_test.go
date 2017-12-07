package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ClosePathFrame", func() {
	Context("when writing", func() {
		var b *bytes.Buffer

		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		Context("self-consistency", func() {
			It("writes a simple ClosePath frame", func() {
				frameOrig := &ClosePathFrame{
					PathID:       7,
					LargestAcked: 1,
					LowestAcked:  1,
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.PathID).To(Equal(frameOrig.PathID))
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes the correct block length in a simple ClosePath frame", func() {
				frameOrig := &ClosePathFrame{
					PathID:       7,
					LargestAcked: 20,
					LowestAcked:  10,
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.PathID).To(Equal(frameOrig.PathID))
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes a simple ClosePath frame with a high packet number", func() {
				frameOrig := &ClosePathFrame{
					PathID:       4,
					LargestAcked: 0xDEADBEEFCAFE,
					LowestAcked:  0xDEADBEEFCAFE,
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.PathID).To(Equal(frameOrig.PathID))
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.HasMissingRanges()).To(BeFalse())
				Expect(r.Len()).To(BeZero())
			})

			It("writes an ClosePath frame with one packet missing", func() {
				frameOrig := &ClosePathFrame{
					PathID:       8,
					LargestAcked: 40,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{First: 25, Last: 40},
						{First: 1, Last: 23},
					},
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.PathID).To(Equal(frameOrig.PathID))
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
				Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				Expect(r.Len()).To(BeZero())
			})

			It("writes an ClosePath frame with multiple missing packets", func() {
				frameOrig := &ClosePathFrame{
					PathID:       1,
					LargestAcked: 25,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{First: 22, Last: 25},
						{First: 15, Last: 18},
						{First: 13, Last: 13},
						{First: 1, Last: 10},
					},
				}
				err := frameOrig.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				r := bytes.NewReader(b.Bytes())
				frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.PathID).To(Equal(frameOrig.PathID))
				Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
				Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
				Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				Expect(r.Len()).To(BeZero())
			})

			It("rejects a frame with incorrect LargestObserved value", func() {
				frame := &ClosePathFrame{
					PathID:       2,
					LargestAcked: 26,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{First: 12, Last: 25},
						{First: 1, Last: 10},
					},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(errInconsistentAckLargestAcked))
			})

			It("rejects a frame with incorrect LowestObserved value", func() {
				frame := &ClosePathFrame{
					PathID:       1,
					LargestAcked: 25,
					LowestAcked:  2,
					AckRanges: []AckRange{
						{First: 12, Last: 25},
						{First: 1, Last: 10},
					},
				}
				err := frame.Write(b, protocol.VersionWhatever)
				Expect(err).To(MatchError(errInconsistentAckLowestAcked))
			})

			Context("longer gaps between ACK blocks", func() {
				It("only writes one block for 254 lost packets", func() {
					frameOrig := &ClosePathFrame{
						PathID:       5,
						LargestAcked: 300,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 20 + 254, Last: 300},
							{First: 1, Last: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(2)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("only writes one block for 255 lost packets", func() {
					frameOrig := &ClosePathFrame{
						PathID:       4,
						LargestAcked: 300,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 20 + 255, Last: 300},
							{First: 1, Last: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(2)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes two blocks for 256 lost packets", func() {
					frameOrig := &ClosePathFrame{
						PathID:       8,
						LargestAcked: 300,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 20 + 256, Last: 300},
							{First: 1, Last: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(3)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					// Expect(b.Bytes()[13+0*(1+6) : 13+1*(1+6)]).To(Equal([]byte{0xFF, 0, 0, 0, 0, 0, 0}))
					// Expect(b.Bytes()[13+1*(1+6) : 13+2*(1+6)]).To(Equal([]byte{0x1, 0, 0, 0, 0, 0, 19}))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes two blocks for 510 lost packets", func() {
					frameOrig := &ClosePathFrame{
						PathID:       27,
						LargestAcked: 600,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 20 + 510, Last: 600},
							{First: 1, Last: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(3)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes three blocks for 511 lost packets", func() {
					frameOrig := &ClosePathFrame{
						PathID:       8,
						LargestAcked: 600,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 20 + 511, Last: 600},
							{First: 1, Last: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(4)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes three blocks for 512 lost packets", func() {
					frameOrig := &ClosePathFrame{
						PathID:       3,
						LargestAcked: 600,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 20 + 512, Last: 600},
							{First: 1, Last: 19},
						},
					}
					Expect(frameOrig.numWritableNackRanges()).To(Equal(uint64(4)))
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes multiple blocks for a lot of lost packets", func() {
					frameOrig := &ClosePathFrame{
						PathID:       42,
						LargestAcked: 3000,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 2900, Last: 3000},
							{First: 1, Last: 19},
						},
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})

				It("writes multiple longer blocks for 256 lost packets", func() {
					frameOrig := &ClosePathFrame{
						PathID:       11,
						LargestAcked: 3600,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 2900, Last: 3600},
							{First: 1000, Last: 2500},
							{First: 1, Last: 19},
						},
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
				})
			})

			Context("longer ACK blocks", func() {
				It("writes a 1 byte Missing Sequence Number Delta", func() {
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: 200,
						LowestAcked:  1,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[2] & 0x3).To(Equal(byte(0x0)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 2 byte Missing Sequence Number Delta", func() {
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: 0x100,
						LowestAcked:  1,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[2] & 0x3).To(Equal(byte(0x1)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 4 byte Missing Sequence Number Delta", func() {
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: 0x10000,
						LowestAcked:  1,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[2] & 0x3).To(Equal(byte(0x2)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 6 byte Missing Sequence Number Delta", func() {
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: 0x100000000,
						LowestAcked:  1,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[2] & 0x3).To(Equal(byte(0x3)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 1 byte Missing Sequence Number Delta, if all ACK blocks are short", func() {
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: 5001,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 5000, Last: 5001},
							{First: 250, Last: 300},
							{First: 1, Last: 200},
						},
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[2] & 0x3).To(Equal(byte(0x0)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})

				It("writes a 2 byte Missing Sequence Number Delta, for a frame with 2 ACK ranges", func() {
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: 10000,
						LowestAcked:  1,
						AckRanges: []AckRange{
							{First: 9990, Last: 10000},
							{First: 1, Last: 256},
						},
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Bytes()[2] & 0x3).To(Equal(byte(0x1)))
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(frameOrig.LowestAcked))
					Expect(frame.AckRanges).To(Equal(frameOrig.AckRanges))
					Expect(r.Len()).To(BeZero())
				})
			})

			Context("too many ACK blocks", func() {
				It("skips the lowest ACK ranges, if there are more than 255 AckRanges", func() {
					ackRanges := make([]AckRange, 300)
					for i := 1; i <= 300; i++ {
						ackRanges[300-i] = AckRange{First: protocol.PacketNumber(3 * i), Last: protocol.PacketNumber(3*i + 1)}
					}
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: ackRanges[0].Last,
						LowestAcked:  ackRanges[len(ackRanges)-1].First,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(ackRanges[254].First))
					Expect(frame.AckRanges).To(HaveLen(0xFF))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})

				It("skips the lowest ACK ranges, if the gaps are large", func() {
					ackRanges := make([]AckRange, 100)
					// every AckRange will take 4 written ACK ranges
					for i := 1; i <= 100; i++ {
						ackRanges[100-i] = AckRange{First: protocol.PacketNumber(1000 * i), Last: protocol.PacketNumber(1000*i + 1)}
					}
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: ackRanges[0].Last,
						LowestAcked:  ackRanges[len(ackRanges)-1].First,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.LowestAcked).To(Equal(ackRanges[255/4].First))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})

				It("works with huge gaps", func() {
					ackRanges := []AckRange{
						{First: 2 * 255 * 200, Last: 2*255*200 + 1},
						{First: 1 * 255 * 200, Last: 1*255*200 + 1},
						{First: 1, Last: 2},
					}
					frameOrig := &ClosePathFrame{
						PathID:       1,
						LargestAcked: ackRanges[0].Last,
						LowestAcked:  ackRanges[len(ackRanges)-1].First,
						AckRanges:    ackRanges,
					}
					err := frameOrig.Write(b, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					r := bytes.NewReader(b.Bytes())
					frame, err := ParseClosePathFrame(r, protocol.VersionWhatever)
					Expect(err).ToNot(HaveOccurred())
					Expect(frame.PathID).To(Equal(frameOrig.PathID))
					Expect(frame.LargestAcked).To(Equal(frameOrig.LargestAcked))
					Expect(frame.AckRanges).To(HaveLen(2))
					Expect(frame.LowestAcked).To(Equal(ackRanges[1].First))
					Expect(frame.validateAckRanges()).To(BeTrue())
				})
			})
		})

		Context("min length", func() {
			It("has proper min length", func() {
				f := &ClosePathFrame{
					LargestAcked: 1,
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has proper min length with a large LargestObserved", func() {
				f := &ClosePathFrame{
					LargestAcked: 0xDEADBEEFCAFE,
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with missing packets", func() {
				f := &ClosePathFrame{
					PathID:       30,
					LargestAcked: 2000,
					LowestAcked:  10,
					AckRanges: []AckRange{
						{First: 1000, Last: 2000},
						{First: 50, Last: 900},
						{First: 10, Last: 23},
					},
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with long gaps of missing packets", func() {
				f := &ClosePathFrame{
					LargestAcked: 2000,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{First: 1500, Last: 2000},
						{First: 290, Last: 295},
						{First: 1, Last: 19},
					},
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})

			It("has the proper min length for an ACK with a long ACK range", func() {
				largestAcked := protocol.PacketNumber(2 + 0xFFFFFF)
				f := &ClosePathFrame{
					PathID:       1,
					LargestAcked: largestAcked,
					LowestAcked:  1,
					AckRanges: []AckRange{
						{First: 1500, Last: largestAcked},
						{First: 290, Last: 295},
						{First: 1, Last: 19},
					},
				}
				err := f.Write(b, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
			})
		})
	})

	Context("ACK range validator", func() {
		It("accepts an ClosePath without NACK Ranges", func() {
			ack := ClosePathFrame{LargestAcked: 7}
			Expect(ack.validateAckRanges()).To(BeTrue())
		})

		It("rejects ACK ranges with a single range", func() {
			ack := ClosePathFrame{
				LargestAcked: 10,
				AckRanges:    []AckRange{{First: 1, Last: 10}},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with Last of the first range unequal to LargestObserved", func() {
			ack := ClosePathFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{First: 8, Last: 9},
					{First: 2, Last: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with First greater than Last", func() {
			ack := ClosePathFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{First: 8, Last: 10},
					{First: 4, Last: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges with First greater than LargestObserved", func() {
			ack := ClosePathFrame{
				LargestAcked: 5,
				AckRanges: []AckRange{
					{First: 4, Last: 10},
					{First: 1, Last: 2},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges in the wrong order", func() {
			ack := ClosePathFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{First: 2, Last: 2},
					{First: 6, Last: 7},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects with overlapping ACK ranges", func() {
			ack := ClosePathFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{First: 5, Last: 7},
					{First: 2, Last: 5},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects ACK ranges that are part of a larger ACK range", func() {
			ack := ClosePathFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{First: 4, Last: 7},
					{First: 5, Last: 6},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("rejects with directly adjacent ACK ranges", func() {
			ack := ClosePathFrame{
				LargestAcked: 7,
				AckRanges: []AckRange{
					{First: 5, Last: 7},
					{First: 2, Last: 4},
				},
			}
			Expect(ack.validateAckRanges()).To(BeFalse())
		})

		It("accepts an ClosePath with one lost packet", func() {
			ack := ClosePathFrame{
				LargestAcked: 10,
				AckRanges: []AckRange{
					{First: 5, Last: 10},
					{First: 1, Last: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeTrue())
		})

		It("accepts an ClosePath with multiple lost packets", func() {
			ack := ClosePathFrame{
				LargestAcked: 20,
				AckRanges: []AckRange{
					{First: 15, Last: 20},
					{First: 10, Last: 12},
					{First: 1, Last: 3},
				},
			}
			Expect(ack.validateAckRanges()).To(BeTrue())
		})
	})

	Context("check if ClosePath frame acks a certain packet", func() {
		It("works with an ClosePath without any ranges", func() {
			f := ClosePathFrame{
				LowestAcked:  5,
				LargestAcked: 10,
			}
			Expect(f.AcksPacket(1)).To(BeFalse())
			Expect(f.AcksPacket(4)).To(BeFalse())
			Expect(f.AcksPacket(5)).To(BeTrue())
			Expect(f.AcksPacket(8)).To(BeTrue())
			Expect(f.AcksPacket(10)).To(BeTrue())
			Expect(f.AcksPacket(11)).To(BeFalse())
			Expect(f.AcksPacket(20)).To(BeFalse())
		})

		It("works with an ACK with multiple ACK ranges", func() {
			f := ClosePathFrame{
				LowestAcked:  5,
				LargestAcked: 20,
				AckRanges: []AckRange{
					{First: 15, Last: 20},
					{First: 5, Last: 8},
				},
			}
			Expect(f.AcksPacket(4)).To(BeFalse())
			Expect(f.AcksPacket(5)).To(BeTrue())
			Expect(f.AcksPacket(7)).To(BeTrue())
			Expect(f.AcksPacket(8)).To(BeTrue())
			Expect(f.AcksPacket(9)).To(BeFalse())
			Expect(f.AcksPacket(14)).To(BeFalse())
			Expect(f.AcksPacket(15)).To(BeTrue())
			Expect(f.AcksPacket(18)).To(BeTrue())
			Expect(f.AcksPacket(20)).To(BeTrue())
			Expect(f.AcksPacket(21)).To(BeFalse())
		})
	})
})
