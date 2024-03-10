package tun

import (
	"errors"
	"runtime"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/mycoria/mycoria/mgr"
)

const readSegments = 32

func (d *Device) tunReader(w *mgr.WorkerCtx) error {
	builder := d.instance.FrameBuilder()
	getMTU := d.instance.Config().TunMTU
	sizes := make([]int, readSegments)
	slices := make([][]byte, readSegments)

	for {
		// Refill all empty segments.
		mtu := getMTU()
		for i := 0; i < readSegments; i++ {
			if sizes[i] == 0 {
				sizes[i] = mtu
				slices[i] = builder.GetPooledSlice(mtu)
			}
		}

		// Read from tun device.
		segments, err := d.Read(slices, sizes, 0)
		if err != nil {
			// Check if we are done before handling the error.
			if w.IsDone() {
				return nil
			}

			// Important: If an error is returned, there might still be successfully
			// read packets.
			switch {
			case errors.Is(err, tun.ErrTooManySegments):
				// TODO: Read sometimes returns ErrTooManySegments
				// This is probably because it would have liked to send more segments,
				// but there werent any left to write to.
				// Code location: https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/offload_linux.go#L924
				// Probably only linux is affected.
				w.Error("not enough read segments, consider increasing", "segments", readSegments)

			default:
				w.Error("failed to read packet", "err", err)
			}

		}

		// Process read segments.
		for i := 0; i < segments; i++ {
			// Skip empty segments.
			if sizes[i] == 0 {
				continue
			}

			// w.Debug(
			// 	"reading packets from tun",
			// 	"slice", i,
			// 	"size", sizes[i],
			// )

			// Get data from return values.
			data := slices[i][:sizes[i]]
			sizes[i] = 0
			slices[i] = nil

			// Submit data to next handler.
			select {
			case d.RecvRaw <- data:
			default:
				select {
				case d.RecvRaw <- data:
				case <-w.Done():
					return nil
				}
			}
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
