package plugins

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
)

func nativeModbusFixture(request []byte, pdu []byte) []byte {
	b := append([]byte(nil), request[:7]...)
	binary.BigEndian.PutUint16(b[4:], uint16(1+len(pdu)))
	return append(b, pdu...)
}

func TestNativeBinaryModbus(t *testing.T) {
	nativeBinaryCases(t, ModbusFingerprinter{}, func(request []byte) []byte {
		if string(request[6:]) != "\x01\x2b\x0e\x01\x00" {
			t.Error("expected basic identification for unit 1")
		}
		return nativeModbusFixture(request, []byte{0x2b, 14, 1, 1, 0, 0, 3, 0, 3, 'A', 'B', 'C', 1, 1, 'P', 2, 1, '7'})
	}, map[string]func([]byte) []byte{
		"wrong_transaction": func(b []byte) []byte { b[1] ^= 1; return b },
		"wrong_protocol":    func(b []byte) []byte { b[3] = 1; return b },
		"wrong_unit":        func(b []byte) []byte { b[6] = 2; return b },
		"wrong_function":    func(b []byte) []byte { b[7] = 3; return b },
		"oversized":         func(b []byte) []byte { binary.BigEndian.PutUint16(b[4:], 255); return b[:7] },
		"bad_object_length": func(b []byte) []byte { b[15] = 255; return b },
		"bad_object_count":  func(b []byte) []byte { b[13] = 4; return b },
		"bad_conformity":    func(b []byte) []byte { b[10] = 0; return b },
		"bad_continuation":  func(b []byte) []byte { b[11] = 0xff; return b },
		"truncated":         func(b []byte) []byte { return b[:len(b)-1] },
	}, map[string]string{"vendor": "ABC", "product": "P", "revision": "7"})
	nativeBinaryCases(t, ModbusFingerprinter{}, func(request []byte) []byte {
		return nativeModbusFixture(request, []byte{0xab, 1})
	}, map[string]func([]byte) []byte{
		"invalid_exception": func(b []byte) []byte { b[8] = 0; return b },
	}, map[string]string{"exceptionCode": "1"})
}

func TestNativeBinaryModbusPagination(t *testing.T) {
	port := nativeBinaryServe(t, func(conn net.Conn) {
		for i := byte(0); i < 3; i++ {
			request := nativeBinaryRequest(t, conn, "modbus")
			if request == nil {
				return
			}
			if request[10] != i {
				t.Error("wrong next object")
			}
			more, next := byte(255), i+1
			if i == 2 {
				more, next = 0, 0
			}
			_, _ = conn.Write(nativeModbusFixture(request, []byte{0x2b, 14, 1, 1, more, next, 1, i, 1, 'A' + i}))
		}
	})
	result, err := (ModbusFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.Generic.Metadata["revision"] != "C" {
		t.Fatal("pagination lost objects")
	}
}
