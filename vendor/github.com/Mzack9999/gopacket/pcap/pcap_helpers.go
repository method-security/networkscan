// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

import "unsafe"

func byteSliceToString(bval []byte) string {
	for i := range bval {
		if bval[i] == 0 {
			return string(bval[:i])
		}
	}
	return string(bval[:])
}

// bytePtrToString returns a string copied from pointer to a null terminated byte array.
// WARNING: ONLY SAFE IF r POINTS TO C MEMORY!
func bytePtrToString(r uintptr) string {
	if r == 0 {
		return ""
	}
	bval := (*[1 << 30]byte)(unsafe.Pointer(r))
	return byteSliceToString(bval[:])
}
