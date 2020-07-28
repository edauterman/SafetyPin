/*
 * Copyright (c) 2018, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2018, University of California, Berkeley
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package lqibe

/*
#include "lqibe/lqibe.h"
*/
import "C"

import "unsafe"

// ParamsMarshalledSize returns the size of a marshalled Params object in
// bytes.
func ParamsMarshalledSize(compressed bool) int {
	return int(C.embedded_pairing_lqibe_params_get_marshalled_length(C._Bool(compressed)))
}

// Marshal encodes a Params object into a byte slice in either compressed or
// uncompressed form, depending on the argument.
func (p *Params) Marshal(compressed bool) []byte {
	length := ParamsMarshalledSize(compressed)
	marshalled := make([]byte, length)
	C.embedded_pairing_lqibe_params_marshal(unsafe.Pointer(&marshalled[0]), &p.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers a Params object from a byte slice, which must encode
// either its compressed or uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (p *Params) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	if C.embedded_pairing_lqibe_params_get_marshalled_length(C._Bool(compressed)) != C.size_t(len(marshalled)) {
		return false
	}
	return bool(C.embedded_pairing_lqibe_params_unmarshal(&p.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}

// IDMarshalledSize returns the size of a marshalled ID object, in bytes.
func IDMarshalledSize(compressed bool) int {
	return int(C.embedded_pairing_lqibe_id_get_marshalled_length(C._Bool(compressed)))
}

// Marshal encodes an ID object into a byte slice in either compressed or
// uncompressed form, depending on the argument.
func (id *ID) Marshal(compressed bool) []byte {
	length := IDMarshalledSize(compressed)
	marshalled := make([]byte, length)
	C.embedded_pairing_lqibe_id_marshal(unsafe.Pointer(&marshalled[0]), &id.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers an ID object from a byte slice, which must encode
// either its compressed or uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (id *ID) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	if C.embedded_pairing_lqibe_id_get_marshalled_length(C._Bool(compressed)) != C.size_t(len(marshalled)) {
		return false
	}
	return bool(C.embedded_pairing_lqibe_id_unmarshal(&id.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}

// MasterKeyMarshalledSize returns the size of a marshalled MasterKey object,
// in bytes.
func MasterKeyMarshalledSize(compressed bool) int {
	return int(C.embedded_pairing_lqibe_masterkey_get_marshalled_length(C._Bool(compressed)))
}

// Marshal encodes a MasterKey object into a byte slice in either compressed or
// uncompressed form, depending on the argument.
func (msk *MasterKey) Marshal(compressed bool) []byte {
	length := MasterKeyMarshalledSize(compressed)
	marshalled := make([]byte, length)
	C.embedded_pairing_lqibe_masterkey_marshal(unsafe.Pointer(&marshalled[0]), &msk.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers a MasterKey object from a byte slice, which must encode
// either its compressed or uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (msk *MasterKey) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	if C.embedded_pairing_lqibe_masterkey_get_marshalled_length(C._Bool(compressed)) != C.size_t(len(marshalled)) {
		return false
	}
	return bool(C.embedded_pairing_lqibe_masterkey_unmarshal(&msk.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}

// SecretKeyMarshalledSize returns the size of a marshalled SecretKey object,
// in bytes.
func SecretKeyMarshalledSize(compressed bool) int {
	return int(C.embedded_pairing_lqibe_secretkey_get_marshalled_length(C._Bool(compressed)))
}

// Marshal encodes a SecretKey object into a byte slice in either compressed or
// uncompressed form, depending on the argument.
func (sk *SecretKey) Marshal(compressed bool) []byte {
	length := SecretKeyMarshalledSize(compressed)
	marshalled := make([]byte, length)
	C.embedded_pairing_lqibe_secretkey_marshal(unsafe.Pointer(&marshalled[0]), &sk.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers a SecretKey object from a byte slice, which must encode
// either its compressed or uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (sk *SecretKey) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	if C.embedded_pairing_lqibe_secretkey_get_marshalled_length(C._Bool(compressed)) != C.size_t(len(marshalled)) {
		return false
	}
	return bool(C.embedded_pairing_lqibe_secretkey_unmarshal(&sk.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}

// CiphertextMarshalledSize returns the size of a marshalled Ciphertext object,
// in bytes.
func CiphertextMarshalledSize(compressed bool) int {
	return int(C.embedded_pairing_lqibe_ciphertext_get_marshalled_length(C._Bool(compressed)))
}

// Marshal encodes a Ciphertext object into a byte slice in either compressed
// or uncompressed form, depending on the argument.
func (c *Ciphertext) Marshal(compressed bool) []byte {
	length := CiphertextMarshalledSize(compressed)
	marshalled := make([]byte, length)
	C.embedded_pairing_lqibe_ciphertext_marshal(unsafe.Pointer(&marshalled[0]), &c.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers a Ciphertext object from a byte slice, which must encode
// either its compressed or uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (c *Ciphertext) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	if C.embedded_pairing_lqibe_ciphertext_get_marshalled_length(C._Bool(compressed)) != C.size_t(len(marshalled)) {
		return false
	}
	return bool(C.embedded_pairing_lqibe_ciphertext_unmarshal(&c.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}
