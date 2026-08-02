// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build !windows
// +build !windows

package pcap

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/Mzack9999/gopacket"
	"github.com/Mzack9999/gopacket/layers"
	"golang.org/x/sys/unix"
)

var pcapLoaded = false

var (
	pcapHandle  uintptr
	pcapLoadErr error
)

var (
	pcapStrerrorPtr,
	pcapStatustostrPtr,
	pcapOpenLivePtr,
	pcapOpenOfflinePtr,
	pcapClosePtr,
	pcapGeterrPtr,
	pcapStatsPtr,
	pcapCompilePtr,
	pcapFreecodePtr,
	pcapLookupnetPtr,
	pcapOfflineFilterPtr,
	pcapSetfilterPtr,
	pcapListDatalinksPtr,
	pcapFreeDatalinksPtr,
	pcapDatalinkValToNamePtr,
	pcapDatalinkValToDescriptionPtr,
	pcapOpenDeadPtr,
	pcapNextExPtr,
	pcapDatalinkPtr,
	pcapSetDatalinkPtr,
	pcapDatalinkNameToValPtr,
	pcapLibVersionPtr,
	pcapFreealldevsPtr,
	pcapFindalldevsPtr,
	pcapSendpacketPtr,
	pcapSetdirectionPtr,
	pcapSnapshotPtr,
	pcapTstampTypeValToNamePtr,
	pcapTstampTypeNameToValPtr,
	pcapListTstampTypesPtr,
	pcapFreeTstampTypesPtr,
	pcapSetTstampTypePtr,
	pcapGetTstampPrecisionPtr,
	pcapSetTstampPrecisionPtr,
	pcapOpenOfflineWithTstampPrecisionPtr,
	pcapActivatePtr,
	pcapCreatePtr,
	pcapSetSnaplenPtr,
	pcapSetPromiscPtr,
	pcapSetTimeoutPtr,
	pcapCanSetRfmonPtr,
	pcapSetRfmonPtr,
	pcapSetBufferSizePtr,
	pcapSetImmediateModePtr,
	pcapSetNonBlockPtr,
	pcapGetSelectableFdPtr uintptr
)

func init() {
	LoadUnixPCAP()
}

// LoadUnixPCAP attempts to dynamically load the libpcap shared library and resolve necessary functions.
func LoadUnixPCAP() error {
	if pcapLoaded {
		return pcapLoadErr
	}

	names := []string{
		"libpcap.so.1",
		"libpcap.so",
		"libpcap.dylib",
		"libpcap.so.0.8",
	}
	for _, name := range names {
		pcapHandle, pcapLoadErr = purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if pcapLoadErr == nil {
			break
		}
	}
	if pcapLoadErr != nil {
		pcapLoadErr = fmt.Errorf("couldn't load libpcap: %w", pcapLoadErr)
		pcapLoaded = true
		return pcapLoadErr
	}

	pcapStrerrorPtr = mustLoad("pcap_strerror")
	pcapStatustostrPtr = mightLoad("pcap_statustostr")
	pcapOpenLivePtr = mustLoad("pcap_open_live")
	pcapOpenOfflinePtr = mustLoad("pcap_open_offline")
	pcapClosePtr = mustLoad("pcap_close")
	pcapGeterrPtr = mustLoad("pcap_geterr")
	pcapStatsPtr = mustLoad("pcap_stats")
	pcapCompilePtr = mustLoad("pcap_compile")
	pcapFreecodePtr = mustLoad("pcap_freecode")
	pcapLookupnetPtr = mustLoad("pcap_lookupnet")
	pcapOfflineFilterPtr = mustLoad("pcap_offline_filter")
	pcapSetfilterPtr = mustLoad("pcap_setfilter")
	pcapListDatalinksPtr = mustLoad("pcap_list_datalinks")
	pcapFreeDatalinksPtr = mustLoad("pcap_free_datalinks")
	pcapDatalinkValToNamePtr = mustLoad("pcap_datalink_val_to_name")
	pcapDatalinkValToDescriptionPtr = mustLoad("pcap_datalink_val_to_description")
	pcapOpenDeadPtr = mustLoad("pcap_open_dead")
	pcapNextExPtr = mustLoad("pcap_next_ex")
	pcapDatalinkPtr = mustLoad("pcap_datalink")
	pcapSetDatalinkPtr = mustLoad("pcap_set_datalink")
	pcapDatalinkNameToValPtr = mustLoad("pcap_datalink_name_to_val")
	pcapLibVersionPtr = mustLoad("pcap_lib_version")
	pcapFreealldevsPtr = mustLoad("pcap_freealldevs")
	pcapFindalldevsPtr = mustLoad("pcap_findalldevs")
	pcapSendpacketPtr = mustLoad("pcap_sendpacket")
	pcapSetdirectionPtr = mustLoad("pcap_setdirection")
	pcapSnapshotPtr = mustLoad("pcap_snapshot")
	pcapTstampTypeValToNamePtr = mightLoad("pcap_tstamp_type_val_to_name")
	pcapTstampTypeNameToValPtr = mightLoad("pcap_tstamp_type_name_to_val")
	pcapListTstampTypesPtr = mightLoad("pcap_list_tstamp_types")
	pcapFreeTstampTypesPtr = mightLoad("pcap_free_tstamp_types")
	pcapSetTstampTypePtr = mightLoad("pcap_set_tstamp_type")
	pcapGetTstampPrecisionPtr = mightLoad("pcap_get_tstamp_precision")
	pcapSetTstampPrecisionPtr = mightLoad("pcap_set_tstamp_precision")
	pcapOpenOfflineWithTstampPrecisionPtr = mightLoad("pcap_open_offline_with_tstamp_precision")
	pcapActivatePtr = mustLoad("pcap_activate")
	pcapCreatePtr = mustLoad("pcap_create")
	pcapSetSnaplenPtr = mustLoad("pcap_set_snaplen")
	pcapSetPromiscPtr = mustLoad("pcap_set_promisc")
	pcapSetTimeoutPtr = mustLoad("pcap_set_timeout")
	pcapCanSetRfmonPtr = mightLoad("pcap_can_set_rfmon")
	pcapSetRfmonPtr = mightLoad("pcap_set_rfmon")
	pcapSetBufferSizePtr = mustLoad("pcap_set_buffer_size")
	pcapSetImmediateModePtr = mightLoad("pcap_set_immediate_mode")
	pcapSetNonBlockPtr = mustLoad("pcap_setnonblock")
	pcapGetSelectableFdPtr = mustLoad("pcap_get_selectable_fd")

	pcapLoaded = true
	return nil
}

func mustLoad(name string) uintptr {
	sym, err := purego.Dlsym(pcapHandle, name)
	if err != nil {
		panic(fmt.Sprintf("couldn't load function %s from libpcap: %v", name, err))
	}
	return sym
}

func mightLoad(name string) uintptr {
	sym, _ := purego.Dlsym(pcapHandle, name)
	return sym
}

func (h *pcapPkthdr) getSec() int64 {
	return int64(h.Ts.Sec)
}

func (h *pcapPkthdr) getUsec() int64 {
	return int64(h.Ts.Usec)
}

func (h *pcapPkthdr) getLen() int {
	return int(h.Len)
}

func (h *pcapPkthdr) getCaplen() int {
	return int(h.Caplen)
}

func statusError(status pcapCint) error {
	var ret uintptr
	if pcapStatustostrPtr == 0 {
		ret, _, _ = purego.SyscallN(pcapStrerrorPtr, uintptr(status))
	} else {
		ret, _, _ = purego.SyscallN(pcapStatustostrPtr, uintptr(status))
	}
	return errors.New(bytePtrToString(ret))
}

func pcapGetTstampPrecision(cptr pcapTPtr) int {
	if pcapGetTstampPrecisionPtr == 0 {
		return pcapTstampPrecisionMicro
	}
	ret, _, _ := purego.SyscallN(pcapGetTstampPrecisionPtr, uintptr(cptr))
	return int(pcapCint(ret))
}

func pcapSetTstampPrecision(cptr pcapTPtr, precision int) error {
	if pcapSetTstampPrecisionPtr == 0 {
		return errors.New("not supported")
	}
	ret, _, _ := purego.SyscallN(pcapSetTstampPrecisionPtr, uintptr(cptr), uintptr(precision))
	if pcapCint(ret) < 0 {
		return errors.New("not supported")
	}
	return nil
}

func pcapOpenLive(device string, snaplen int, pro int, timeout int) (*Handle, error) {
	err := LoadUnixPCAP()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, errorBufferSize)
	dev, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}

	cptr, _, _ := purego.SyscallN(pcapOpenLivePtr,
		uintptr(unsafe.Pointer(dev)),
		uintptr(snaplen),
		uintptr(pro),
		uintptr(timeout),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if cptr == 0 {
		return nil, errors.New(byteSliceToString(buf))
	}
	return &Handle{cptr: pcapTPtr(cptr)}, nil
}

func openOffline(file string) (handle *Handle, err error) {
	err = LoadUnixPCAP()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, errorBufferSize)
	f, err := syscall.BytePtrFromString(file)
	if err != nil {
		return nil, err
	}

	var cptr uintptr
	if pcapOpenOfflineWithTstampPrecisionPtr == 0 {
		cptr, _, _ = purego.SyscallN(pcapOpenOfflinePtr,
			uintptr(unsafe.Pointer(f)),
			uintptr(unsafe.Pointer(&buf[0])),
		)
	} else {
		cptr, _, _ = purego.SyscallN(pcapOpenOfflineWithTstampPrecisionPtr,
			uintptr(unsafe.Pointer(f)),
			uintptr(pcapTstampPrecisionNano),
			uintptr(unsafe.Pointer(&buf[0])),
		)
	}
	if cptr == 0 {
		return nil, errors.New(byteSliceToString(buf))
	}
	return &Handle{cptr: pcapTPtr(cptr)}, nil
}

func (p *Handle) pcapClose() {
	if p.cptr != 0 {
		purego.SyscallN(pcapClosePtr, uintptr(p.cptr))
	}
	p.cptr = 0
}

func (p *Handle) pcapGeterr() error {
	ret, _, _ := purego.SyscallN(pcapGeterrPtr, uintptr(p.cptr))
	return errors.New(bytePtrToString(ret))
}

func (p *Handle) pcapStats() (*Stats, error) {
	var cstats pcapStats
	ret, _, _ := purego.SyscallN(pcapStatsPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&cstats)))
	if pcapCint(ret) < 0 {
		return nil, p.pcapGeterr()
	}
	return &Stats{
		PacketsReceived:  int(cstats.Recv),
		PacketsDropped:   int(cstats.Drop),
		PacketsIfDropped: int(cstats.Ifdrop),
	}, nil
}

// for libpcap < 1.8 pcap_compile is NOT thread-safe, so protect it.
var pcapCompileMu sync.Mutex

func (p *Handle) pcapCompile(expr string, maskp uint32) (pcapBpfProgram, error) {
	var bpf pcapBpfProgram
	cexpr, err := syscall.BytePtrFromString(expr)
	if err != nil {
		return pcapBpfProgram{}, err
	}
	pcapCompileMu.Lock()
	defer pcapCompileMu.Unlock()
	res, _, _ := purego.SyscallN(pcapCompilePtr,
		uintptr(p.cptr),
		uintptr(unsafe.Pointer(&bpf)),
		uintptr(unsafe.Pointer(cexpr)),
		uintptr(1),
		uintptr(maskp),
	)
	if pcapCint(res) < 0 {
		return bpf, p.pcapGeterr()
	}
	return bpf, nil
}

func (p pcapBpfProgram) free() {
	purego.SyscallN(pcapFreecodePtr, uintptr(unsafe.Pointer(&p)))
}

func (p pcapBpfProgram) toBPFInstruction() []BPFInstruction {
	bpfInsn := (*[bpfInstructionBufferSize]pcapBpfInstruction)(unsafe.Pointer(p.Insns))[0:p.Len:p.Len]
	bpfInstruction := make([]BPFInstruction, len(bpfInsn))

	for i, v := range bpfInsn {
		bpfInstruction[i].Code = v.Code
		bpfInstruction[i].Jt = v.Jt
		bpfInstruction[i].Jf = v.Jf
		bpfInstruction[i].K = v.K
	}
	return bpfInstruction
}

func pcapBpfProgramFromInstructions(bpfInstructions []BPFInstruction) pcapBpfProgram {
	var bpf pcapBpfProgram
	bpf.Len = uint32(len(bpfInstructions))
	insns := make([]pcapBpfInstruction, len(bpfInstructions))

	for i, v := range bpfInstructions {
		insns[i].Code = v.Code
		insns[i].Jt = v.Jt
		insns[i].Jf = v.Jf
		insns[i].K = v.K
	}

	bpf.Insns = &insns[0]
	runtime.KeepAlive(insns)
	return bpf
}

func pcapLookupnet(device string) (netp, maskp uint32, err error) {
	err = LoadUnixPCAP()
	if err != nil {
		return 0, 0, err
	}

	buf := make([]byte, errorBufferSize)
	dev, err := syscall.BytePtrFromString(device)
	if err != nil {
		return 0, 0, err
	}
	e, _, _ := purego.SyscallN(pcapLookupnetPtr,
		uintptr(unsafe.Pointer(dev)),
		uintptr(unsafe.Pointer(&netp)),
		uintptr(unsafe.Pointer(&maskp)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if pcapCint(e) < 0 {
		return 0, 0, errors.New(byteSliceToString(buf))
	}
	return
}

func (b *BPF) pcapOfflineFilter(ci gopacket.CaptureInfo, data []byte) bool {
	hdr := &b.hdr
	hdr.Ts = unix.NsecToTimeval(ci.Timestamp.UnixNano())
	hdr.Caplen = uint32(len(data))
	hdr.Len = uint32(ci.Length)
	e, _, _ := purego.SyscallN(pcapOfflineFilterPtr,
		uintptr(unsafe.Pointer(&b.bpf.bpf)),
		uintptr(unsafe.Pointer(hdr)),
		uintptr(unsafe.Pointer(&data[0])),
	)
	return e != 0
}

func (p *Handle) pcapSetfilter(bpf pcapBpfProgram) error {
	e, _, _ := purego.SyscallN(pcapSetfilterPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&bpf)))
	if pcapCint(e) < 0 {
		return p.pcapGeterr()
	}
	return nil
}

func (p *Handle) pcapListDatalinks() (datalinks []Datalink, err error) {
	var dltbuf *pcapCint

	ret, _, _ := purego.SyscallN(pcapListDatalinksPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&dltbuf)))
	n := int(pcapCint(ret))
	if n < 0 {
		return nil, p.pcapGeterr()
	}
	defer purego.SyscallN(pcapFreeDatalinksPtr, uintptr(unsafe.Pointer(dltbuf)))

	datalinks = make([]Datalink, n)
	dltArray := (*[1 << 28]pcapCint)(unsafe.Pointer(dltbuf))

	for i := 0; i < n; i++ {
		datalinks[i].Name = pcapDatalinkValToName(int((*dltArray)[i]))
		datalinks[i].Description = pcapDatalinkValToDescription(int((*dltArray)[i]))
	}

	return datalinks, nil
}

func pcapOpenDead(linkType layers.LinkType, captureLength int) (*Handle, error) {
	err := LoadUnixPCAP()
	if err != nil {
		return nil, err
	}

	cptr, _, _ := purego.SyscallN(pcapOpenDeadPtr, uintptr(linkType), uintptr(captureLength))
	if cptr == 0 {
		return nil, errors.New("error opening dead capture")
	}

	return &Handle{cptr: pcapTPtr(cptr)}, nil
}

func (p *Handle) pcapNextPacketEx() NextError {
	r, _, _ := purego.SyscallN(pcapNextExPtr,
		uintptr(p.cptr),
		uintptr(unsafe.Pointer(&p.pkthdr)),
		uintptr(unsafe.Pointer(&p.bufptr)),
	)
	ret := pcapCint(r)
	if ret > 1 {
		ret = 1
	}
	return NextError(ret)
}

func (p *Handle) pcapDatalink() layers.LinkType {
	ret, _, _ := purego.SyscallN(pcapDatalinkPtr, uintptr(p.cptr))
	return layers.LinkType(ret)
}

func (p *Handle) pcapSetDatalink(dlt layers.LinkType) error {
	ret, _, _ := purego.SyscallN(pcapSetDatalinkPtr, uintptr(p.cptr), uintptr(dlt))
	if pcapCint(ret) < 0 {
		return p.pcapGeterr()
	}
	return nil
}

func pcapDatalinkValToName(dlt int) string {
	err := LoadUnixPCAP()
	if err != nil {
		panic(err)
	}
	ret, _, _ := purego.SyscallN(pcapDatalinkValToNamePtr, uintptr(dlt))
	return bytePtrToString(ret)
}

func pcapDatalinkValToDescription(dlt int) string {
	err := LoadUnixPCAP()
	if err != nil {
		panic(err)
	}
	ret, _, _ := purego.SyscallN(pcapDatalinkValToDescriptionPtr, uintptr(dlt))
	return bytePtrToString(ret)
}

func pcapDatalinkNameToVal(name string) int {
	err := LoadUnixPCAP()
	if err != nil {
		return 0
	}
	cptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0
	}
	ret, _, _ := purego.SyscallN(pcapDatalinkNameToValPtr, uintptr(unsafe.Pointer(cptr)))
	return int(pcapCint(ret))
}

func pcapLibVersion() string {
	err := LoadUnixPCAP()
	if err != nil {
		panic(err)
	}
	ret, _, _ := purego.SyscallN(pcapLibVersionPtr)
	return bytePtrToString(ret)
}

func (p *Handle) isOpen() bool {
	return p.cptr != 0
}

type pcapDevices struct {
	all, cur *pcapIf
}

func (p pcapDevices) free() {
	purego.SyscallN(pcapFreealldevsPtr, uintptr(unsafe.Pointer(p.all)))
}

func (p *pcapDevices) next() bool {
	if p.cur == nil {
		p.cur = p.all
		if p.cur == nil {
			return false
		}
		return true
	}
	if p.cur.Next == nil {
		return false
	}
	p.cur = p.cur.Next
	return true
}

func (p pcapDevices) name() string {
	return bytePtrToString(uintptr(unsafe.Pointer(p.cur.Name)))
}

func (p pcapDevices) description() string {
	return bytePtrToString(uintptr(unsafe.Pointer(p.cur.Description)))
}

func (p pcapDevices) flags() uint32 {
	return p.cur.Flags
}

type pcapAddresses struct {
	all, cur *pcapAddr
}

func (p *pcapAddresses) next() bool {
	if p.cur == nil {
		p.cur = p.all
		if p.cur == nil {
			return false
		}
		return true
	}
	if p.cur.Next == nil {
		return false
	}
	p.cur = p.cur.Next
	return true
}

func (p pcapAddresses) addr() *syscall.RawSockaddr {
	return p.cur.Addr
}

func (p pcapAddresses) netmask() *syscall.RawSockaddr {
	return p.cur.Netmask
}

func (p pcapAddresses) broadaddr() *syscall.RawSockaddr {
	return p.cur.Broadaddr
}

func (p pcapAddresses) dstaddr() *syscall.RawSockaddr {
	return p.cur.Dstaddr
}

func (p pcapDevices) addresses() pcapAddresses {
	return pcapAddresses{all: p.cur.Addresses}
}

func pcapFindAllDevs() (pcapDevices, error) {
	var alldevsp pcapDevices
	err := LoadUnixPCAP()
	if err != nil {
		return alldevsp, err
	}

	buf := make([]byte, errorBufferSize)

	ret, _, _ := purego.SyscallN(pcapFindalldevsPtr,
		uintptr(unsafe.Pointer(&alldevsp.all)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if pcapCint(ret) < 0 {
		return pcapDevices{}, errors.New(byteSliceToString(buf))
	}
	return alldevsp, nil
}

func (p *Handle) pcapSendpacket(data []byte) error {
	ret, _, _ := purego.SyscallN(pcapSendpacketPtr,
		uintptr(p.cptr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
	)
	if pcapCint(ret) < 0 {
		return p.pcapGeterr()
	}
	return nil
}

func (p *Handle) pcapSetdirection(direction Direction) error {
	status, _, _ := purego.SyscallN(pcapSetdirectionPtr, uintptr(p.cptr), uintptr(direction))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *Handle) pcapSnapshot() int {
	ret, _, _ := purego.SyscallN(pcapSnapshotPtr, uintptr(p.cptr))
	return int(pcapCint(ret))
}

func (t TimestampSource) pcapTstampTypeValToName() string {
	err := LoadUnixPCAP()
	if err != nil {
		return err.Error()
	}

	if pcapTstampTypeValToNamePtr == 0 {
		return "pcap timestamp types not supported"
	}
	ret, _, _ := purego.SyscallN(pcapTstampTypeValToNamePtr, uintptr(t))
	return bytePtrToString(ret)
}

func pcapTstampTypeNameToVal(s string) (TimestampSource, error) {
	err := LoadUnixPCAP()
	if err != nil {
		return 0, err
	}

	if pcapTstampTypeNameToValPtr == 0 {
		return 0, statusError(pcapCint(pcapError))
	}
	cs, err := syscall.BytePtrFromString(s)
	if err != nil {
		return 0, err
	}
	ret, _, _ := purego.SyscallN(pcapTstampTypeNameToValPtr, uintptr(unsafe.Pointer(cs)))
	t := pcapCint(ret)
	if t < 0 {
		return 0, statusError(t)
	}
	return TimestampSource(t), nil
}

func (p *InactiveHandle) pcapGeterr() error {
	ret, _, _ := purego.SyscallN(pcapGeterrPtr, uintptr(p.cptr))
	return errors.New(bytePtrToString(ret))
}

func (p *InactiveHandle) pcapActivate() (*Handle, activateError) {
	r, _, _ := purego.SyscallN(pcapActivatePtr, uintptr(p.cptr))
	ret := activateError(pcapCint(r))
	if ret != aeNoError {
		return nil, ret
	}
	h := &Handle{
		cptr: p.cptr,
	}
	p.cptr = 0
	return h, ret
}

func (p *InactiveHandle) pcapClose() {
	if p.cptr != 0 {
		purego.SyscallN(pcapClosePtr, uintptr(p.cptr))
	}
	p.cptr = 0
}

func pcapCreate(device string) (*InactiveHandle, error) {
	err := LoadUnixPCAP()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, errorBufferSize)
	dev, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	cptr, _, _ := purego.SyscallN(pcapCreatePtr,
		uintptr(unsafe.Pointer(dev)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if cptr == 0 {
		return nil, errors.New(byteSliceToString(buf))
	}
	return &InactiveHandle{cptr: pcapTPtr(cptr)}, nil
}

func (p *InactiveHandle) pcapSetSnaplen(snaplen int) error {
	status, _, _ := purego.SyscallN(pcapSetSnaplenPtr, uintptr(p.cptr), uintptr(snaplen))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetPromisc(promisc bool) error {
	var pro uintptr
	if promisc {
		pro = 1
	}
	status, _, _ := purego.SyscallN(pcapSetPromiscPtr, uintptr(p.cptr), pro)
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetTimeout(timeout time.Duration) error {
	status, _, _ := purego.SyscallN(pcapSetTimeoutPtr, uintptr(p.cptr), uintptr(timeoutMillis(timeout)))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapListTstampTypes() (out []TimestampSource) {
	if pcapListTstampTypesPtr == 0 {
		return
	}
	var types *pcapCint
	ret, _, _ := purego.SyscallN(pcapListTstampTypesPtr, uintptr(p.cptr), uintptr(unsafe.Pointer(&types)))
	n := int(pcapCint(ret))
	if n < 0 {
		return
	}
	defer purego.SyscallN(pcapFreeTstampTypesPtr, uintptr(unsafe.Pointer(types)))
	typesArray := (*[1 << 28]pcapCint)(unsafe.Pointer(types))
	for i := 0; i < n; i++ {
		out = append(out, TimestampSource((*typesArray)[i]))
	}
	return
}

func (p *InactiveHandle) pcapSetTstampType(t TimestampSource) error {
	if pcapSetTstampTypePtr == 0 {
		return statusError(pcapError)
	}
	status, _, _ := purego.SyscallN(pcapSetTstampTypePtr, uintptr(p.cptr), uintptr(t))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetRfmon(monitor bool) error {
	if pcapCanSetRfmonPtr == 0 {
		return CannotSetRFMon
	}
	var mon uintptr
	if monitor {
		mon = 1
	}
	canset, _, _ := purego.SyscallN(pcapCanSetRfmonPtr, uintptr(p.cptr))
	switch canset {
	case 0:
		return CannotSetRFMon
	case 1:
		// success
	default:
		return statusError(pcapCint(canset))
	}
	status, _, _ := purego.SyscallN(pcapSetRfmonPtr, uintptr(p.cptr), mon)
	if status != 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetBufferSize(bufferSize int) error {
	status, _, _ := purego.SyscallN(pcapSetBufferSizePtr, uintptr(p.cptr), uintptr(bufferSize))
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *InactiveHandle) pcapSetImmediateMode(mode bool) error {
	if pcapSetImmediateModePtr == 0 {
		return statusError(pcapError)
	}
	var md uintptr
	if mode {
		md = 1
	}
	status, _, _ := purego.SyscallN(pcapSetImmediateModePtr, uintptr(p.cptr), md)
	if pcapCint(status) < 0 {
		return statusError(pcapCint(status))
	}
	return nil
}

func (p *Handle) setNonBlocking() error {
	buf := make([]byte, errorBufferSize)

	v, _, _ := purego.SyscallN(pcapSetNonBlockPtr,
		uintptr(p.cptr),
		uintptr(1),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if int32(v) < -1 {
		return errors.New(byteSliceToString(buf))
	}

	return nil
}

// waitForPacket waits for a packet or for the timeout to expire.
func (p *Handle) waitForPacket() {
	fdRet, _, _ := purego.SyscallN(pcapGetSelectableFdPtr, uintptr(p.cptr))
	fd := int32(fdRet)
	if fd < 0 {
		return
	}

	tmMs := timeoutMillis(p.timeout)
	if tmMs == 0 {
		tmMs = -1
	}
	fds := []unix.PollFd{{Fd: fd, Events: unix.POLLIN}}
	unix.Poll(fds, tmMs)
}

// openOfflineFile returns contents of input file as a *Handle.
func openOfflineFile(file *os.File) (handle *Handle, err error) {
	return openOffline(fmt.Sprintf("/dev/fd/%d", file.Fd()))
}
