package tun

import (
	"github.com/mycoria/mycoria/mgr"
)

// TODO: Read more at once.

func (d *Device) tunReader(w *mgr.WorkerCtx) error {
	builder := d.instance.FrameBuilder()
	getMTU := d.instance.Config().TunMTU

	mtu := getMTU()
	pooledSlice := builder.GetPooledSlice(mtu)
	sizes := []int{mtu}

	for {
		sizes[0] = mtu
		packets, err := d.Read([][]byte{pooledSlice}, sizes, 0)
		if err != nil {
			// Check if we are done before handling the error.
			if w.IsDone() {
				return nil
			}

			// TODO: Read sometimes returns ErrTooManySegments
			// This might be due to (missing?) offset.
			// Code location: https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/offload_linux.go#L924
			// Probably only linux is affected.

			w.Error("failed to read packet", "err", err)
			continue
		}
		if packets == 1 {
			data := pooledSlice[:sizes[0]]
			select {
			case d.RecvRaw <- data:
			default:
				select {
				case d.RecvRaw <- data:
				case <-w.Done():
					return nil
				}
			}

			mtu := getMTU()
			pooledSlice = builder.GetPooledSlice(mtu)
		}
	}
}

func (d *Device) tunWriter(w *mgr.WorkerCtx) error {
	b := d.instance.FrameBuilder()

	for {
		select {
		case packetData := <-d.SendRaw:
			dataWritten, err := d.Write([][]byte{packetData}, 0)
			b.ReturnPooledSlice(packetData)
			if err != nil {
				w.Error("failed to write packet", "err", err)
			} else if dataWritten != len(packetData) {
				w.Error(
					"failed to write all packet data",
					"written",
					dataWritten,
					"total",
					len(packetData),
				)
			}

		case f := <-d.SendFrame:
			var dataWritten int
			packetData, err := f.MessageDataWithOffset(10)
			if err == nil {
				dataWritten, err = d.Write([][]byte{packetData}, 10)
			}
			f.ReturnToPool()
			if err != nil {
				w.Error("failed to write packet", "err", err)
			} else if dataWritten != len(packetData) {
				w.Error(
					"failed to write all packet data",
					"written",
					dataWritten,
					"total",
					len(packetData),
				)
			}

		case <-w.Done():
			return nil
		}
	}
}
