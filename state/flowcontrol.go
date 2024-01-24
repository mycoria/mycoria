package state

// TODO:
// Implement connection flow controlling:
// type ConnectionFlow struct {
// 	sync.Mutex

// 	// Sequence Numbers

// 	SentSeqPriority   uint32
// 	RecvSeqPriority   [10]uint32
// 	SeqLossesPriority uint32

// 	SentSeqNormal   uint32
// 	RecvSeqNormal   [100]uint32
// 	SeqLossesNormal uint32

// 	// Latency Testing
// 	// Latency is tested with priority frames.

// 	// LatencyTestStarted holds the local time when the latency test was started.
// 	LatencyTestStarted time.Time
// 	// LatencyTestSeqNum  is set to the current sequence number at the start of the test.
// 	LatencyTestSeqNum uint32
// 	// LatencyTestResult is updated with the measurement as soon as LatencyTestSeqNum is acknowledged.
// 	// Calculation: Milliseconds(Now - Start Time)
// 	LatencyTestResult uint32 // Milliseconds

// 	// Bandwidth Testing
// 	// Bandwidth is tested with normal frames.

// 	// BandwidthTestStart holds the local time when the bandwidth test was started.
// 	BandwidthTestStart time.Time
// 	// BandwidthTestSeqStart is set to the current sequence number at the start of the test.
// 	BandwidthTestSeqStart uint32
// 	// BandwidthTestSeqEnd is set to the last sequence number included in the test.
// 	BandwidthTestSeqEnd uint32
// 	// BandwidthTestBytes holds the total amount of bytes of start to end sequence numbers.
// 	BandwidthTestBytes uint32
// 	// BandwidthResult is updated with the measurement as soon as BandwidthTestSeqEnd is acknowledged.
// 	// Calculation: BandwidthTestBytes / Seconds(Now - Start Time - LatencyTestResult)
// 	BandwidthResult uint32 // Bytes/Second
// }
