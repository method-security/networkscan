// Package vnc implements RFB (VNC) protocol enumeration.
package vnc

import (
	// Standard
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net"
	"strconv"
	"strings"
	"time"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	vncfern "github.com/Method-Security/networkscan/generated/go/enumerate/vnc"

	// Internal
	"github.com/Method-Security/networkscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const (
	defaultVNCPort      = 5900
	defaultPortRangeStr = "5900-5910"
	maxFramebufferBytes = 16 * 1024 * 1024 // 16 MiB
	rfbHandshakeTimeout = 10 * time.Second
)

// securityTypeMap maps numeric RFB security type values to VncSecurityType enums.
var securityTypeMap = map[byte]vncfern.VncSecurityType{
	1:  vncfern.VncSecurityTypeNone,
	2:  vncfern.VncSecurityTypeVncAuth,
	5:  vncfern.VncSecurityTypeRa2,
	6:  vncfern.VncSecurityTypeRa2Ne,
	16: vncfern.VncSecurityTypeTight,
	17: vncfern.VncSecurityTypeUltra,
	18: vncfern.VncSecurityTypeTls,
	19: vncfern.VncSecurityTypeVencrypt,
	20: vncfern.VncSecurityTypeSasl,
	21: vncfern.VncSecurityTypeMd5Hash,
	22: vncfern.VncSecurityTypeXvp,
	30: vncfern.VncSecurityTypeMacArd,
	35: vncfern.VncSecurityTypeArdExtended,
}

// LibraryEnumerateVNC implements NetworkApplicationLibrary for VNC/RFB enumeration.
type LibraryEnumerateVNC struct {
	SkipScreenshot bool
	PortRange      string
}

// EnumerateTarget performs RFB/VNC enumeration against a single target.
//
// Flow:
//  1. Parse target; if no port given, sweep portRange (default 5900-5910)
//  2. Dial, read 12-byte RFB banner, negotiate version
//  3. Read advertised security types
//  4. If None auth offered: send ClientInit, read ServerInit, optionally capture screenshot
//  5. Compute weak deployment findings
func (l *LibraryEnumerateVNC) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting VNC enumeration", svc1log.SafeParam("target", target))

	errors := []string{}

	host, port := utils.ParseHostPort(target, 0)
	hasExplicitPort := (port != 0)

	// Build list of ports to probe. With no explicit port, sweep the configured
	// range — falling back through PortRange → default literal → defaultVNCPort
	// only here (the per-port path no longer re-defaults, avoiding the duplicate
	// fallback chain).
	var ports []int
	if hasExplicitPort {
		ports = []int{port}
	} else {
		portRange := l.PortRange
		if portRange == "" {
			portRange = defaultPortRangeStr
		}
		ports = parsePortRange(portRange)
		if len(ports) == 0 {
			ports = []int{defaultVNCPort}
		}
	}

	// Share the caller's context deadline across all per-port probes so a sweep
	// of 11 ports doesn't exceed the EnumerateServiceConfig.Timeout. Without
	// this, an 11-port sweep with a 10s per-port deadline (rfbHandshakeTimeout)
	// can run for ~110s under the default 30s tool timeout.
	var allDetails []*vncfern.EnumerateVncDetails
	for _, p := range ports {
		// Stop early if the shared deadline expired (the next probePort would
		// just record connect-deadline-exceeded for every remaining port).
		if err := ctx.Err(); err != nil {
			errors = append(errors, fmt.Sprintf("port %d: ctx: %v", p, err))
			break
		}
		detail := probePort(ctx, log, host, p, l.SkipScreenshot)
		allDetails = append(allDetails, detail)
		if detail.Errors != nil {
			for _, e := range detail.Errors {
				errors = append(errors, fmt.Sprintf("port %d: %s", p, e))
			}
		}
		// Early-exit on first RFB-speaking listener — ProtocolVersion is only
		// set after the 12-byte banner validates as "RFB xxx.yyy\n", so this is
		// a stronger success signal than canConnect (TCP-level only).
		if detail.ProtocolVersion != nil {
			break
		}
	}

	// Return the first detail that actually spoke RFB (not just any port that
	// answered TCP — a sibling service on 5901 with no RFB banner would
	// otherwise mask a real VNC listener on 5902). Fall back to canConnect, and
	// only then to the last attempt.
	if len(allDetails) == 1 {
		return &enumeratefern.EnumerateServiceDetails{EnumerateVncDetails: allDetails[0]}, errors
	}
	for _, d := range allDetails {
		if d.ProtocolVersion != nil {
			return &enumeratefern.EnumerateServiceDetails{EnumerateVncDetails: d}, errors
		}
	}
	for _, d := range allDetails {
		if d.CanConnect != nil && *d.CanConnect {
			return &enumeratefern.EnumerateServiceDetails{EnumerateVncDetails: d}, errors
		}
	}
	if len(allDetails) > 0 {
		return &enumeratefern.EnumerateServiceDetails{EnumerateVncDetails: allDetails[len(allDetails)-1]}, errors
	}

	// Fallback — no ports probed (e.g. ctx cancelled before the loop body ran).
	fallbackPort := defaultVNCPort
	if hasExplicitPort {
		fallbackPort = port
	}
	detail := &vncfern.EnumerateVncDetails{Target: target, Port: fallbackPort}
	return &enumeratefern.EnumerateServiceDetails{EnumerateVncDetails: detail}, errors
}

// probePort performs the RFB handshake on a single host:port.
func probePort(ctx context.Context, log svc1log.Logger, host string, port int, skipScreenshot bool) *vncfern.EnumerateVncDetails {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	target := addr
	detail := &vncfern.EnumerateVncDetails{Target: target, Port: port}
	errs := []string{}

	// Determine connection deadline from context
	deadline := time.Now().Add(rfbHandshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		canConnect := false
		detail.CanConnect = &canConnect
		errs = append(errs, fmt.Sprintf("vnc connect: %v", err))
		detail.Errors = errs
		return detail
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(deadline); err != nil {
		errs = append(errs, fmt.Sprintf("vnc set deadline: %v", err))
		detail.Errors = errs
		return detail
	}

	canConnect := true
	detail.CanConnect = &canConnect

	// Read 12-byte RFB version banner: "RFB xxx.yyy\n"
	banner := make([]byte, 12)
	if _, err := readFull(conn, banner); err != nil {
		errs = append(errs, fmt.Sprintf("vnc banner read: %v", err))
		detail.Errors = errs
		return detail
	}

	bannerStr := string(banner)
	if !strings.HasPrefix(bannerStr, "RFB ") {
		errs = append(errs, fmt.Sprintf("vnc banner: unexpected prefix: %q", bannerStr))
		detail.Errors = errs
		return detail
	}

	// Parse version: "RFB MAJ.MIN\n"
	versionStr := strings.TrimSpace(bannerStr[4:])
	detail.ProtocolVersion = &versionStr

	serverMajor, serverMinor, err := parseRFBVersion(versionStr)
	if err != nil {
		errs = append(errs, fmt.Sprintf("vnc version parse: %v", err))
		detail.Errors = errs
		return detail
	}

	// Negotiate version: send min(server, 003.008)
	clientMajor, clientMinor := 3, 8
	if serverMajor < clientMajor || (serverMajor == clientMajor && serverMinor < clientMinor) {
		clientMajor = serverMajor
		clientMinor = serverMinor
	}
	clientVersionMsg := fmt.Sprintf("RFB %03d.%03d\n", clientMajor, clientMinor)
	if _, err := conn.Write([]byte(clientVersionMsg)); err != nil {
		errs = append(errs, fmt.Sprintf("vnc version send: %v", err))
		detail.Errors = errs
		return detail
	}

	// Read security types
	var advertisedTypes []vncfern.VncSecurityType
	var unknownTypes []int
	var noneOffered, vncAuthOffered, vencryptOffered, tlsTunneled bool
	var noneTypeNum byte

	if serverMajor == 3 && serverMinor < 7 {
		// RFB 3.3: server sends single uint32 security type. A value of 0
		// signals rejection — the server then sends a uint32 reason length and
		// the reason string. Treat that as a connection failure rather than
		// silently dropping into screenshot capture against a stream that
		// continues with the reason bytes.
		var secType uint32
		if err := binary.Read(conn, binary.BigEndian, &secType); err != nil {
			errs = append(errs, fmt.Sprintf("vnc security type read (3.3): %v", err))
			detail.Errors = errs
			return detail
		}
		if secType == 0 {
			var reasonLen uint32
			if err := binary.Read(conn, binary.BigEndian, &reasonLen); err != nil {
				errs = append(errs, "vnc 3.3 server rejected connection (no reason)")
			} else if reasonLen > 0 && reasonLen < 1024 {
				reason := make([]byte, reasonLen)
				if _, err := readFull(conn, reason); err == nil {
					errs = append(errs, fmt.Sprintf("vnc 3.3 server rejected: %s", string(reason)))
				} else {
					errs = append(errs, fmt.Sprintf("vnc 3.3 server rejected (reason read: %v)", err))
				}
			} else {
				errs = append(errs, fmt.Sprintf("vnc 3.3 server rejected (unexpected reason length %d)", reasonLen))
			}
			detail.Errors = errs
			return detail
		}
		if st, ok := securityTypeMap[byte(secType)]; ok {
			advertisedTypes = append(advertisedTypes, st)
		} else {
			unknownTypes = append(unknownTypes, int(secType))
		}
		categorizeSecType(byte(secType), &noneOffered, &vncAuthOffered, &vencryptOffered, &tlsTunneled)
		noneTypeNum = byte(secType)
	} else {
		// RFB 3.7+: read uint8 N followed by N security type bytes
		var numTypes uint8
		if err := binary.Read(conn, binary.BigEndian, &numTypes); err != nil {
			errs = append(errs, fmt.Sprintf("vnc security type count read: %v", err))
			detail.Errors = errs
			return detail
		}

		if numTypes == 0 {
			// Server sent 0 types followed by a reason string (failure)
			var reasonLen uint32
			if err := binary.Read(conn, binary.BigEndian, &reasonLen); err != nil {
				errs = append(errs, "vnc connection failed (0 security types)")
			} else if reasonLen > 0 && reasonLen < 1024 {
				reason := make([]byte, reasonLen)
				if _, err := readFull(conn, reason); err == nil {
					errs = append(errs, fmt.Sprintf("vnc server refused: %s", string(reason)))
				}
			}
			detail.Errors = errs
			return detail
		}

		typeBytes := make([]byte, numTypes)
		if _, err := readFull(conn, typeBytes); err != nil {
			errs = append(errs, fmt.Sprintf("vnc security types read: %v", err))
			detail.Errors = errs
			return detail
		}

		for _, tb := range typeBytes {
			if st, ok := securityTypeMap[tb]; ok {
				advertisedTypes = append(advertisedTypes, st)
			} else {
				unknownTypes = append(unknownTypes, int(tb))
			}
			categorizeSecType(tb, &noneOffered, &vncAuthOffered, &vencryptOffered, &tlsTunneled)
		}
		// Remember None type byte for selection
		if noneOffered {
			noneTypeNum = 1
		}
	}

	if len(advertisedTypes) > 0 {
		detail.AdvertisedSecurityTypes = advertisedTypes
	}
	if len(unknownTypes) > 0 {
		detail.UnknownSecurityTypes = unknownTypes
	}
	detail.NoneAuthOffered = boolPtr(noneOffered)
	detail.VncAuthOffered = boolPtr(vncAuthOffered)
	detail.VencryptOffered = boolPtr(vencryptOffered)
	detail.TlsTunneled = boolPtr(tlsTunneled)

	// Compute weak deployment findings
	weakFindings := computeWeakFindings(advertisedTypes, vncAuthOffered, vencryptOffered, tlsTunneled)
	if len(weakFindings) > 0 {
		detail.WeakDeploymentFindings = weakFindings
	}

	// If None auth is offered, proceed with anonymous login to collect server
	// info (desktop name, framebuffer dims, pixel format, none_auth_accepted).
	// `--vnc-skip-screenshot` is *only* a guard on the framebuffer download —
	// see doNoneAuth, which gates the SetPixelFormat → FramebufferUpdateRequest
	// dance on `skipScreenshot` instead of skipping the entire authenticated
	// branch. Otherwise we'd lose the ServerInit metadata, which is the
	// reconnaissance intel the ticket actually wants.
	if noneOffered {
		if err := doNoneAuth(conn, detail, serverMajor, serverMinor, noneTypeNum, deadline, skipScreenshot); err != nil {
			errs = append(errs, fmt.Sprintf("vnc none auth: %v", err))
		}
	}

	if len(errs) > 0 {
		detail.Errors = errs
	}
	return detail
}

// categorizeSecType sets boolean flags for a given security type byte.
func categorizeSecType(tb byte, noneOffered, vncAuthOffered, vencryptOffered, tlsTunneled *bool) {
	switch tb {
	case 1:
		*noneOffered = true
	case 2:
		*vncAuthOffered = true
	case 18:
		*tlsTunneled = true
	case 19:
		*vencryptOffered = true
	}
}

// doNoneAuth performs anonymous (None) authentication, reads ServerInit, and
// optionally captures a framebuffer screenshot. NoneAuthAccepted is *only* set
// after ServerInit completes successfully — earlier we incorrectly stamped it
// true right after the security handshake, so a server that disconnected
// between SecurityResult and ServerInit produced false-positive
// none_auth_accepted=true intel.
//
// When skipScreenshot is true, ServerInit metadata (desktop name, framebuffer
// dimensions, pixel format, none_auth_accepted) is still captured — only the
// SetPixelFormat + FramebufferUpdateRequest dance is skipped.
func doNoneAuth(
	conn net.Conn,
	detail *vncfern.EnumerateVncDetails,
	serverMajor, serverMinor int,
	noneTypeNum byte,
	deadline time.Time,
	skipScreenshot bool,
) error {
	// For RFB 3.7+, we need to select the security type (send [1] for None)
	if serverMajor > 3 || (serverMajor == 3 && serverMinor >= 7) {
		if _, err := conn.Write([]byte{noneTypeNum}); err != nil {
			return fmt.Errorf("security type select: %w", err)
		}
	}

	// RFB 3.8+: read SecurityResult (uint32, 0=OK, 1=failed)
	if serverMajor > 3 || (serverMajor == 3 && serverMinor >= 8) {
		var secResult uint32
		if err := binary.Read(conn, binary.BigEndian, &secResult); err != nil {
			return fmt.Errorf("security result read: %w", err)
		}
		if secResult != 0 {
			// Read reason
			var reasonLen uint32
			if err := binary.Read(conn, binary.BigEndian, &reasonLen); err == nil && reasonLen < 1024 {
				reason := make([]byte, reasonLen)
				if _, err := readFull(conn, reason); err == nil {
					return fmt.Errorf("security result failed: %s", string(reason))
				}
			}
			return fmt.Errorf("security result failed (code %d)", secResult)
		}
	}

	// Send ClientInit{shared=1}
	if _, err := conn.Write([]byte{1}); err != nil {
		return fmt.Errorf("client init: %w", err)
	}

	// Read ServerInit: u16 width, u16 height, 16-byte pixel format, u32 nameLen, name
	var width, height uint16
	if err := binary.Read(conn, binary.BigEndian, &width); err != nil {
		return fmt.Errorf("server init width: %w", err)
	}
	if err := binary.Read(conn, binary.BigEndian, &height); err != nil {
		return fmt.Errorf("server init height: %w", err)
	}

	// Read 16-byte pixel format
	pfBytes := make([]byte, 16)
	if _, err := readFull(conn, pfBytes); err != nil {
		return fmt.Errorf("pixel format read: %w", err)
	}

	// Read desktop name. If nameLen exceeds the 4096-byte cap, we still have to
	// consume the remaining bytes off the stream — otherwise the next read
	// (FramebufferUpdate header, or just connection close) reads the tail of
	// the name and the protocol state desyncs.
	var nameLen uint32
	if err := binary.Read(conn, binary.BigEndian, &nameLen); err != nil {
		return fmt.Errorf("name len read: %w", err)
	}
	const maxDesktopName = 4096
	readLen := nameLen
	if readLen > maxDesktopName {
		readLen = maxDesktopName
	}
	nameBuf := make([]byte, readLen)
	if _, err := readFull(conn, nameBuf); err != nil {
		return fmt.Errorf("desktop name read: %w", err)
	}
	if nameLen > maxDesktopName {
		// Drain the rest of the name bytes from the wire so the next message
		// header lines up with the protocol position.
		remaining := nameLen - maxDesktopName
		discard := make([]byte, 1024)
		for remaining > 0 {
			chunk := uint32(len(discard))
			if chunk > remaining {
				chunk = remaining
			}
			if _, err := readFull(conn, discard[:chunk]); err != nil {
				return fmt.Errorf("desktop name drain: %w", err)
			}
			remaining -= chunk
		}
	}

	// ServerInit completed — NOW it is safe to claim NoneAuth was actually
	// accepted end-to-end.
	noneAccepted := true
	detail.NoneAuthAccepted = &noneAccepted

	// Populate server info
	w := int(width)
	h := int(height)
	detail.FramebufferWidth = &w
	detail.FramebufferHeight = &h
	name := string(nameBuf)
	detail.DesktopName = &name

	// Parse pixel format
	pf := parsePixelFormat(pfBytes)
	detail.PixelFormat = pf

	// The screenshot capture is the only thing `--vnc-skip-screenshot` gates;
	// ServerInit metadata above is always recorded.
	if skipScreenshot {
		return nil
	}

	// Attempt screenshot only if dimensions are reasonable
	totalBytes := int(width) * int(height) * 4
	if totalBytes > maxFramebufferBytes {
		return nil
	}

	// Send SetPixelFormat to force 32bpp BGRA little-endian
	// Message type 0, 3-byte padding, then 16-byte pixel format
	setpfMsg := make([]byte, 20)
	setpfMsg[0] = 0 // SetPixelFormat message type
	// Bytes 1-3: padding
	// Pixel format: 32 bpp, 24 depth, little-endian, true-color
	setpfMsg[4] = 32 // bits-per-pixel
	setpfMsg[5] = 24 // depth
	setpfMsg[6] = 0  // big-endian flag (0 = little-endian)
	setpfMsg[7] = 1  // true-color flag
	// Red max = 255 (0x00FF)
	binary.BigEndian.PutUint16(setpfMsg[8:], 255)
	// Green max = 255
	binary.BigEndian.PutUint16(setpfMsg[10:], 255)
	// Blue max = 255
	binary.BigEndian.PutUint16(setpfMsg[12:], 255)
	setpfMsg[14] = 16 // red shift (B G R A: A=24, R=16, G=8, B=0)
	setpfMsg[15] = 8  // green shift
	setpfMsg[16] = 0  // blue shift
	// Bytes 17-19: padding
	if _, err := conn.Write(setpfMsg); err != nil {
		return fmt.Errorf("set pixel format: %w", err)
	}

	// Send FramebufferUpdateRequest{incremental=0, x=0, y=0, w=width, h=height}
	fburMsg := make([]byte, 10)
	fburMsg[0] = 3                             // FramebufferUpdateRequest message type
	fburMsg[1] = 0                             // incremental = 0 (full update)
	binary.BigEndian.PutUint16(fburMsg[2:], 0) // x
	binary.BigEndian.PutUint16(fburMsg[4:], 0) // y
	binary.BigEndian.PutUint16(fburMsg[6:], width)
	binary.BigEndian.PutUint16(fburMsg[8:], height)
	if _, err := conn.Write(fburMsg); err != nil {
		return fmt.Errorf("framebuffer update request: %w", err)
	}

	// Extend deadline for screenshot download
	_ = conn.SetDeadline(deadline)

	// Read FramebufferUpdate message
	// Header: msg type (1 byte), padding (1 byte), num rects (2 bytes)
	header := make([]byte, 4)
	if _, err := readFull(conn, header); err != nil {
		return fmt.Errorf("framebuffer update header: %w", err)
	}
	if header[0] != 0 {
		// Not a FramebufferUpdate message; might be a ServerCutText or Bell — skip
		return fmt.Errorf("vnc handshake: unexpected server message type %d", header[0])
	}
	numRects := binary.BigEndian.Uint16(header[2:])
	if numRects == 0 {
		return nil
	}

	// Read first rectangle header: x, y, w, h, encoding (each 2 bytes except encoding which is 4)
	rectHeader := make([]byte, 12)
	if _, err := readFull(conn, rectHeader); err != nil {
		return fmt.Errorf("framebuffer rect header: %w", err)
	}
	encoding := int32(binary.BigEndian.Uint32(rectHeader[8:]))
	rectW := binary.BigEndian.Uint16(rectHeader[4:])
	rectH := binary.BigEndian.Uint16(rectHeader[6:])

	if encoding != 0 {
		// Non-Raw encoding; bail without screenshot
		return nil
	}

	// Read raw pixel data: rectW * rectH * 4 bytes (32bpp)
	pixelBytes := int(rectW) * int(rectH) * 4
	if pixelBytes > maxFramebufferBytes {
		return nil
	}
	if pixelBytes == 0 {
		return nil
	}

	rawPixels := make([]byte, pixelBytes)
	if _, err := readFull(conn, rawPixels); err != nil {
		return fmt.Errorf("framebuffer raw pixels: %w", err)
	}

	// Decode raw BGRA to image.NRGBA
	img := image.NewNRGBA(image.Rect(0, 0, int(rectW), int(rectH)))
	for y := 0; y < int(rectH); y++ {
		for x := 0; x < int(rectW); x++ {
			offset := (y*int(rectW) + x) * 4
			b := rawPixels[offset+0]
			g := rawPixels[offset+1]
			r := rawPixels[offset+2]
			a := rawPixels[offset+3]
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
	}

	// Encode to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return fmt.Errorf("png encode: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	detail.ScreenshotPngBase64 = &encoded

	return nil
}

// computeWeakFindings returns a list of weak deployment findings.
func computeWeakFindings(advertisedTypes []vncfern.VncSecurityType, vncAuthOffered, vencryptOffered, tlsTunneled bool) []string {
	var findings []string

	// VNC-Auth offered without TLS or VeNCrypt
	if vncAuthOffered && !tlsTunneled && !vencryptOffered {
		findings = append(findings, "VNC-Auth offered without TLS or VeNCrypt")
	}

	// Check for Tight with auth-capability count zero (we note this as weak)
	for _, st := range advertisedTypes {
		if st == vncfern.VncSecurityTypeTight {
			findings = append(findings, "Tight security type offered (verify auth capability count)")
			break
		}
	}

	return findings
}

// parsePixelFormat decodes 16 bytes of RFB PixelFormat into a VncPixelFormat.
func parsePixelFormat(b []byte) *vncfern.VncPixelFormat {
	if len(b) < 16 {
		return nil
	}
	bpp := int(b[0])
	depth := int(b[1])
	bigEndian := b[2] != 0
	trueColor := b[3] != 0
	redMax := int(binary.BigEndian.Uint16(b[4:]))
	greenMax := int(binary.BigEndian.Uint16(b[6:]))
	blueMax := int(binary.BigEndian.Uint16(b[8:]))
	redShift := int(b[10])
	greenShift := int(b[11])
	blueShift := int(b[12])
	return &vncfern.VncPixelFormat{
		BitsPerPixel: &bpp,
		Depth:        &depth,
		BigEndian:    &bigEndian,
		TrueColor:    &trueColor,
		RedMax:       &redMax,
		GreenMax:     &greenMax,
		BlueMax:      &blueMax,
		RedShift:     &redShift,
		GreenShift:   &greenShift,
		BlueShift:    &blueShift,
	}
}

// parseRFBVersion extracts major and minor version numbers from "MAJ.MIN" string.
// strconv.Atoi already handles leading zeros correctly ("003" → 3), so we use it directly.
func parseRFBVersion(versionStr string) (int, int, error) {
	parts := strings.SplitN(versionStr, ".", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid RFB version: %q", versionStr)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid RFB major version: %q", parts[0])
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid RFB minor version: %q", parts[1])
	}
	return major, minor, nil
}

// parsePortRange parses a port range string like "5900-5910" into a list of ports.
func parsePortRange(portRange string) []int {
	parts := strings.SplitN(portRange, "-", 2)
	if len(parts) == 1 {
		p, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err == nil && p > 0 && p <= 65535 {
			return []int{p}
		}
		return nil
	}
	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
		return nil
	}
	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}

// readFull reads exactly len(buf) bytes from the connection.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}
