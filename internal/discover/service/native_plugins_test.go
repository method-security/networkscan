package service

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestMissingTCPPluginsRejectGarbageAndHonorDeadline(t *testing.T) {
	// The inventory test pins this boundary between existing and newly added plugins.
	newPlugins := false
	for _, plugin := range customFingerprintModules {
		if plugin.Name() == "winbox" {
			newPlugins = true
			continue
		}
		if !newPlugins {
			continue
		}
		for _, silent := range []bool{false, true} {
			t.Run(fmt.Sprintf("%T/silent=%v", plugin, silent), func(t *testing.T) {
				t.Parallel()
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
				defer cancel()
				done := make(chan struct{})
				go func() {
					defer close(done)
					for {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						if silent {
							<-ctx.Done()
						} else {
							_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
							_, _ = conn.Write([]byte("unrelated service response\r\n"))
						}
						_ = conn.Close()
					}
				}()
				t.Cleanup(func() {
					cancel()
					_ = listener.Close()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("test server did not stop")
					}
				})
				start := time.Now()
				result, err := plugin.Detect(ctx, net.ParseIP("127.0.0.1"), listener.Addr().(*net.TCPAddr).Port, "negative.test", 2)
				if result != nil {
					t.Fatalf("false positive: %+v (error %v)", result, err)
				}
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("ignored attempt context: %s", elapsed)
				}
			})
		}
	}
	if !newPlugins {
		t.Fatal("missing registry boundary")
	}
}
