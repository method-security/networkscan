package service

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/plugins"
	snmplib "github.com/Method-Security/networkscan/internal/protocol/snmp"
	"github.com/gosnmp/gosnmp"
)

func snmpDeadlineFixture(t *testing.T, mode string) (int, <-chan struct{}) {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done, received := make(chan struct{}), make(chan struct{}, 1)
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		dropped := false
		for {
			n, addr, err := c.ReadFrom(buffer)
			if err != nil {
				return
			}
			select {
			case received <- struct{}{}:
			default:
			}
			if mode == "silent" {
				continue
			}
			decoder := gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "decoder"}}
			request, err := decoder.SnmpDecodePacket(buffer[:n])
			if err != nil {
				t.Error(err)
				continue
			}
			response := &gosnmp.SnmpPacket{Version: request.Version, Community: request.Community, RequestID: request.RequestID, PDUType: gosnmp.GetResponse}
			if request.Version == gosnmp.Version3 {
				if mode != "all" && mode != "v3-only" && mode != "v3-retry" {
					continue
				}
				security := request.SecurityParameters.(*gosnmp.UsmSecurityParameters)
				if mode == "v3-retry" && !dropped {
					dropped = true
					continue
				}
				if mode != "all" && security.AuthoritativeEngineID != "" {
					continue // Engine discovery succeeds, but optional GETs never answer.
				}
				response.MsgID, response.MsgMaxSize = request.MsgID, 65507
				response.SecurityModel = gosnmp.UserSecurityModel
				response.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: security.UserName, AuthoritativeEngineID: "\x80\x00\x00\x09local", AuthoritativeEngineBoots: 7, AuthoritativeEngineTime: 123}
				response.ContextEngineID = "\x80\x00\x00\x09local"
				if security.AuthoritativeEngineID == "" {
					response.PDUType = gosnmp.Report
					response.Variables = []gosnmp.SnmpPDU{{Name: "1.3.6.1.6.3.15.1.1.4.0", Type: gosnmp.Counter32, Value: uint32(1)}}
				}
			} else if mode != "all" && !(mode == "v1-only" && request.Version == gosnmp.Version1) && !(mode == "v2-only" && request.Version == gosnmp.Version2c) {
				continue
			}
			if response.PDUType == gosnmp.GetResponse {
				for _, variable := range request.Variables {
					response.Variables = append(response.Variables, gosnmp.SnmpPDU{Name: variable.Name, Type: gosnmp.OctetString, Value: "fixture"})
				}
			}
			wire, err := response.MarshalMsg()
			if err != nil {
				t.Error(err)
				continue
			}
			_, _ = c.WriteTo(wire, addr)
		}
	}()
	t.Cleanup(func() { _ = c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr).Port, received
}

func TestSNMPDetectionSurvivesAttemptDeadline(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		versions []string
	}{
		{"v3-only", []string{"SNMPv3"}},
		{"v3-retry", []string{"SNMPv3"}},
		{"v2-only", []string{"SNMPv2c"}},
		{"v1-only", []string{"SNMPv1"}},
		{"all", []string{"SNMPv3", "SNMPv2c", "SNMPv1"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			port, _ := snmpDeadlineFixture(t, tc.mode)
			start := time.Now()
			result, err := runFingerprinterAttempt(context.Background(), 1, func(ctx context.Context) (*discover.ServiceDetails, error) {
				return (plugins.SNMPFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), port, "snmp.test", 1)
			})
			if err != nil || result == nil {
				t.Fatalf("lost valid SNMP detection at attempt deadline: result=%+v err=%v", result, err)
			}
			if elapsed := time.Since(start); elapsed >= time.Second {
				t.Fatalf("detection arrived after deadline: %s", elapsed)
			}
			metadata := result.Metadata.Snmp
			if !reflect.DeepEqual(metadata.Versions, tc.versions) || result.Host != "snmp.test" {
				t.Fatalf("metadata lost: %+v", result)
			}
			if tc.mode == "v3-only" || tc.mode == "v3-retry" || tc.mode == "all" {
				if metadata.V3EngineId == nil || *metadata.V3EngineId != hex.EncodeToString([]byte("\x80\x00\x00\x09local")) || metadata.V3EngineBoots == nil || *metadata.V3EngineBoots != 7 {
					t.Fatalf("engine metadata lost: %+v", metadata)
				}
			}
			if tc.mode != "v3-only" && tc.mode != "v3-retry" && !reflect.DeepEqual(metadata.CommunityStrings, []string{"public", "private"}) {
				t.Fatalf("community metadata lost: %+v", metadata)
			}
		})
	}
}

func TestSNMPPluginCancellation(t *testing.T) {
	port, received := snmpDeadlineFixture(t, "silent")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (plugins.SNMPFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), port, "snmp.test", 10)
		done <- err
	}()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("no discovery request")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SNMP ignored cancellation")
	}
}

func TestSNMPPluginSilentDeadline(t *testing.T) {
	port, _ := snmpDeadlineFixture(t, "silent")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	r, err := (plugins.SNMPFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), port, "snmp.test", -1)
	if r != nil || err == nil || time.Since(start) >= 500*time.Millisecond {
		t.Fatalf("silent server not bounded: result=%+v err=%v elapsed=%s", r, err, time.Since(start))
	}
}

func TestSNMPLegacyHelpersPreserveMetadata(t *testing.T) {
	port, _ := snmpDeadlineFixture(t, "all")
	ip := net.ParseIP("127.0.0.1")
	engine, description, err := snmplib.TrySNMPv3Discovery(ip, uint16(port), 1)
	if err != nil || engine == nil || description != "fixture" || engine.EngineBoots != 7 {
		t.Fatalf("legacy v3 helper changed: engine=%+v description=%q err=%v", engine, description, err)
	}
	for _, version := range []gosnmp.SnmpVersion{gosnmp.Version1, gosnmp.Version2c} {
		ok, info, err := snmplib.TrySNMPCommunityCheck(ip, uint16(port), 1, "public", version)
		if err != nil || !ok || info == nil || info.SysDescr != "fixture" || info.SysName != "fixture" {
			t.Fatalf("legacy community helper changed: version=%v info=%+v err=%v", version, info, err)
		}
	}
}
