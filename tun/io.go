package tun

import (
	"runtime"

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

writeLoop:
	for {
		var (
			packetData []byte
			err        error
			written    int
		)

		// Wait for packet and write.
		select {
		case packetData = <-d.SendRaw:
			written, err = d.Write([][]byte{packetData}, d.sendRawOffset)
			b.ReturnPooledSlice(packetData)

		case f := <-d.SendFrame:
			packetData, err = f.MessageDataWithOffset(10)
			if err == nil {
				written, err = d.Write([][]byte{packetData}, 10)
			}
			f.ReturnToPool()

		case <-w.Done():
			return nil
		}

		// Report write errors.
		if err != nil {
			w.Error("failed to write packet", "err", err)
			continue writeLoop
		}

		// Check if all data was written.
		// The return value is different per OS.
		switch runtime.GOOS {
		case "linux":
			// written is total bytes written.
			if written != len(packetData) {
				w.Error(
					"failed to write all packet data (bytes)",
					"written",
					written,
					"total",
					len(packetData),
				)
			}
		case "windows":
			// written is total bufs written.
			if written != 1 {
				w.Error(
					"failed to write all packet data (bufs)",
					"written",
					written,
					"total",
					1,
				)
			}
		}
	}
}
