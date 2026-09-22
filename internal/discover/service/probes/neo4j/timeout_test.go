package neo4j

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestUnlimitedTimeoutFragmentedReads(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		read    func(net.Conn) ([]byte, error)
	}{
		{"handshake", []byte{0, 0, 0, 5}, func(conn net.Conn) ([]byte, error) { return recvExact(conn, 4, 0) }},
		{"message", []byte{0, 2, 0xb1, 0x70, 0, 0}, func(conn net.Conn) ([]byte, error) { return recvBoltMessageRaw(conn, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			done := make(chan error, 1)
			go func() {
				defer func() { _ = server.Close() }()
				if err := server.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					done <- err
					return
				}
				for _, b := range tc.payload {
					time.Sleep(time.Millisecond)
					if _, err := server.Write([]byte{b}); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			got, err := tc.read(client)
			_ = client.Close()
			if writeErr := <-done; writeErr != nil {
				t.Errorf("write: %v", writeErr)
			}
			if err != nil || !bytes.Equal(got, tc.payload) {
				t.Fatalf("read = %x, %v; want %x", got, err, tc.payload)
			}
		})
	}
}
