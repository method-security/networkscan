package plugins

import (
	"reflect"
	"testing"
)

// Wire-format reference: ASHRAE 135 §6 (BVLC), §6 NPDU, §20 APDU encoding.

// validIAm is a valid BACnet/IP I-Am:
//
//	BVLC  81 0a 00 14         (Original-Unicast-NPDU, length 20)
//	NPDU  01 00                (version 1, control 0)
//	APDU  10 00                (Unconfirmed-Request, service-choice I-Am=0)
//	         c4 02 00 00 07    (BACnetObjectIdentifier device:7)
//	         22 05 c4          (max-APDU 1476)
//	         91 00             (segmentation SEGMENTED_BOTH)
//	         21 01             (vendor-id 1 = ASHRAE)
var validIAm = []byte{
	0x81, 0x0a, 0x00, 0x14,
	0x01, 0x00,
	0x10, 0x00,
	0xc4, 0x02, 0x00, 0x00, 0x07,
	0x22, 0x05, 0xc4,
	0x91, 0x00,
	0x21, 0x01,
}

func TestParseIAm(t *testing.T) {
	got, err := parseIAm(validIAm)
	if err != nil {
		t.Fatalf("parseIAm: %v", err)
	}
	want := &iAmResult{
		deviceInstance: 7,
		maxAPDU:        1476,
		segmentation:   0,
		vendorID:       1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestParseIAm_LargerVendorID(t *testing.T) {
	// vendor-id 534 (0x0216): 22 02 16
	pkt := append([]byte(nil), validIAm[:len(validIAm)-2]...)
	pkt = append(pkt, 0x22, 0x02, 0x16)
	pkt[3] = byte(len(pkt))
	got, err := parseIAm(pkt)
	if err != nil {
		t.Fatalf("parseIAm: %v", err)
	}
	if got.vendorID != 534 {
		t.Errorf("vendorID = %d, want 534", got.vendorID)
	}
}

func TestParseIAm_WithNpduRouting(t *testing.T) {
	// NPDU with source spec set (SNET 0x0001, SLEN 1, SADR 0x05, hop omitted
	// because destination spec is unset).
	// Total APDU + tags = 15. NPDU = 2 + 3 + 1 = 6. BVLC = 4. Total = 25 = 0x19.
	pkt := []byte{
		0x81, 0x0a, 0x00, 0x19,
		0x01, 0x08, // control: source spec
		0x00, 0x01, 0x01, 0x05, // SNET 1, SLEN 1, SADR 5
		0x10, 0x00,
		0xc4, 0x02, 0x00, 0x00, 0x07,
		0x22, 0x05, 0xc4,
		0x91, 0x03, // NO_SEGMENTATION
		0x21, 0x01,
	}
	got, err := parseIAm(pkt)
	if err != nil {
		t.Fatalf("parseIAm: %v", err)
	}
	if got.segmentation != 3 {
		t.Errorf("segmentation = %d, want 3", got.segmentation)
	}
}

func TestParseIAm_Rejects(t *testing.T) {
	tests := map[string][]byte{
		"too short":    {0x81, 0x0a, 0x00},
		"bad BVLC":     {0x82, 0x0a, 0x00, 0x14, 0x01, 0x00, 0x10, 0x00},
		"bad function": {0x81, 0x05, 0x00, 0x14, 0x01, 0x00, 0x10, 0x00},
		// I-Am marker present but APDU type is Confirmed-Request not Unconfirmed.
		// Should reject because the body still lacks the 10 00 sequence —
		// constructed for exhaustiveness.
		"wrong APDU type": {0x81, 0x0a, 0x00, 0x0a, 0x01, 0x00, 0x20, 0x05, 0x01, 0x0c},
	}
	for name, pkt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseIAm(pkt); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestSegmentationName(t *testing.T) {
	for v, want := range map[uint32]string{
		0: "SEGMENTED_BOTH",
		1: "SEGMENTED_TRANSMIT",
		2: "SEGMENTED_RECEIVE",
		3: "NO_SEGMENTATION",
		4: "",
		7: "",
	} {
		if got := segmentationName(v); got != want {
			t.Errorf("segmentationName(%d) = %q, want %q", v, got, want)
		}
	}
}

func TestBuildReadPropertyRequest_VendorName(t *testing.T) {
	got := buildReadPropertyRequest(7, bacnetPropVendorName, 1)
	// Expected wire:
	//   BVLC  81 0a 00 11                        (Original-Unicast, length 17)
	//   NPDU  01 04                              (control: expecting-reply)
	//   APDU  00 05 01 0c                        (Confirmed-Request, max-segs/resp, invokeID, ReadProperty)
	//   ctx0  0c 02 00 00 07                     (ObjID Device:7)
	//   ctx1  19 79                              (PropID 121 = vendor-name)
	want := []byte{
		0x81, 0x0a, 0x00, 0x11,
		0x01, 0x04,
		0x00, 0x05, 0x01, 0x0c,
		0x0c, 0x02, 0x00, 0x00, 0x07,
		0x19, 0x79,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %x\nwant %x", got, want)
	}
}

func TestBuildReadPropertyRequest_PropertyOverByte(t *testing.T) {
	// Property 300 (0x012c) does not fit in 1 byte; expect tag 1a + 2 bytes.
	got := buildReadPropertyRequest(7, 300, 1)
	wantPropID := []byte{0x1a, 0x01, 0x2c}
	tail := got[len(got)-3:]
	if !reflect.DeepEqual(tail, wantPropID) {
		t.Errorf("propID encoded as %x, want %x", tail, wantPropID)
	}
}

func TestParseReadPropertyAck_String(t *testing.T) {
	// ComplexACK ReadProperty for vendor-name returning "ASHRAE".
	//   BVLC  81 0a 00 1b
	//   NPDU  01 00
	//   APDU  30 01 0c
	//   ctx0  0c 02 00 00 07
	//   ctx1  19 79
	//   open  3e
	//   value 75 07 00 41 53 48 52 41 45     ("ASHRAE", encoding 0)
	//   close 3f
	pkt := []byte{
		0x81, 0x0a, 0x00, 0x1b,
		0x01, 0x00,
		0x30, 0x01, 0x0c,
		0x0c, 0x02, 0x00, 0x00, 0x07,
		0x19, 0x79,
		0x3e,
		0x75, 0x07, 0x00, 'A', 'S', 'H', 'R', 'A', 'E',
		0x3f,
	}
	value, err := parseReadPropertyAck(pkt, 1)
	if err != nil {
		t.Fatalf("parseReadPropertyAck: %v", err)
	}
	got, ok := decodeCharString(value)
	if !ok {
		t.Fatalf("decodeCharString failed for %x", value)
	}
	if got != "ASHRAE" {
		t.Errorf("got %q, want ASHRAE", got)
	}
}

func TestParseReadPropertyAck_UnsignedThroughHelper(t *testing.T) {
	// ComplexACK returning protocol-version (98) = 1
	//   ctx0 0c 02 00 00 07
	//   ctx1 19 62      (98)
	//   open 3e
	//   val  21 01      (unsigned 1)
	//   close 3f
	pkt := []byte{
		0x81, 0x0a, 0x00, 0x14,
		0x01, 0x00,
		0x30, 0x02, 0x0c,
		0x0c, 0x02, 0x00, 0x00, 0x07,
		0x19, 0x62,
		0x3e,
		0x21, 0x01,
		0x3f,
	}
	value, err := parseReadPropertyAck(pkt, 2)
	if err != nil {
		t.Fatalf("parseReadPropertyAck: %v", err)
	}
	v, _, err := readAppUnsigned(value, 2)
	if err != nil {
		t.Fatalf("readAppUnsigned: %v", err)
	}
	if v != 1 {
		t.Errorf("got %d, want 1", v)
	}
}

func TestParseReadPropertyAck_InvokeIDMismatch(t *testing.T) {
	pkt := []byte{
		0x81, 0x0a, 0x00, 0x1b,
		0x01, 0x00,
		0x30, 0x01, 0x0c,
		0x0c, 0x02, 0x00, 0x00, 0x07,
		0x19, 0x79,
		0x3e,
		0x75, 0x07, 0x00, 'A', 'S', 'H', 'R', 'A', 'E',
		0x3f,
	}
	if _, err := parseReadPropertyAck(pkt, 9); err == nil {
		t.Errorf("expected invoke-id mismatch error")
	}
}

func TestDecodeCharString_TrimsTrailingNul(t *testing.T) {
	// "AB\x00\x00" -> "AB"
	v := []byte{0x75, 0x05, 0x00, 'A', 'B', 0x00, 0x00}
	got, ok := decodeCharString(v)
	if !ok || got != "AB" {
		t.Errorf("got (%q, %v), want (AB, true)", got, ok)
	}
}

func TestDecodeCharString_UnknownEncoding(t *testing.T) {
	// encoding=3 (UCS-4); filter to printable ASCII.
	v := []byte{0x75, 0x05, 0x03, 'X', 0xff, 'Y', 0x00}
	got, ok := decodeCharString(v)
	if !ok {
		t.Fatalf("decodeCharString failed")
	}
	if got != "XY" {
		t.Errorf("got %q, want XY", got)
	}
}

func TestBACnetFingerprinter_DefaultPorts(t *testing.T) {
	if ports := (BACnetFingerprinter{}).DefaultPorts(); len(ports) != 1 || ports[0] != 47808 {
		t.Errorf("ports = %v, want [47808]", ports)
	}
}

func TestBACnetFingerprinter_Name(t *testing.T) {
	if name := (BACnetFingerprinter{}).Name(); name != "bacnet" {
		t.Errorf("name = %q, want bacnet", name)
	}
}
