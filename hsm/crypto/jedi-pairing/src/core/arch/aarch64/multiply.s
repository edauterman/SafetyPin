// Copyright (c) 2019, Sam Kumar <samkumar@cs.berkeley.edu>
// Copyright (c) 2019, University of California, Berkeley
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// AArch64 calling convention: x0 - x7 are used for call arguments and results,
// x9 - x15 are temporary registers (caller-saved), and x19 - x28 (and sp) must
// be saved/restored if modified (callee-saved). Additionally, x8, x16, and x17
// are reserved for the linker (long branches), x29 is the frame pointer, and
// x30 is the link register (return address). x18 is a "platform register" that
// should not be used in portable code.

// In the macros below, the carry status flag is implicitly part of carry_in
// and carry_out; if the it is one, the actual value is one more than what is
// indicated in the actual register.

.macro multiply64 dst, carry_out, arg0, arg1
    umulh \carry_out, \arg0, \arg1
    mul \dst, \arg0, \arg1
.endm

.macro mulcarry64 dst, carry_out, arg0, arg1, carry_in
    mul \dst, \arg0, \arg1
    umulh \carry_out, \arg0, \arg1
    adcs \dst, \dst, \carry_in
.endm

.macro muladd64 dst, carry_out, arg0, arg1, scratch
    mul \scratch, \arg0, \arg1
    umulh \carry_out, \arg0, \arg1
    adds \dst, \dst, \scratch
.endm

.macro muladdcarry64 dst, carry_out, arg0, arg1, carry_in, scratch
    mul \scratch, \arg0, \arg1
    umulh \carry_out, \arg0, \arg1
    adcs \dst, \dst, \scratch
    adcs \carry_out, \carry_out, xzr
    adds \dst, \dst, \carry_in
.endm

.macro multiply768firstiteration res0, res1, res2, res3, res4, res5, res6, ar0, br0, br1, br2, br3, br4, br5, carry
    adds xzr, xzr, xzr // Clear carry flag
    multiply64 \res0, \carry, \ar0, \br0
    mulcarry64 \res1, \res6, \ar0, \br1, \carry
    mulcarry64 \res2, \carry, \ar0, \br2, \res6
    mulcarry64 \res3, \res6, \ar0, \br3, \carry
    mulcarry64 \res4, \carry, \ar0, \br4, \res6
    mulcarry64 \res5, \res6, \ar0, \br5, \carry
    adcs \res6, \res6, xzr
.endm

.macro multiply768iteration res0, res1, res2, res3, res4, res5, res6, ar0, br0, br1, br2, br3, br4, br5, carry, scratch
    muladd64 \res0, \carry, \ar0, \br0, \scratch
    muladdcarry64 \res1, \res6, \ar0, \br1, \carry, \scratch
    muladdcarry64 \res2, \carry, \ar0, \br2, \res6, \scratch
    muladdcarry64 \res3, \res6, \ar0, \br3, \carry, \scratch
    muladdcarry64 \res4, \carry, \ar0, \br4, \res6, \scratch
    muladdcarry64 \res5, \res6, \ar0, \br5, \carry, \scratch
    adcs \res6, \res6, xzr
.endm

// Sets res := a * b
// Does not preserve a[0] and a[1], but preserves b and the rest of a
.macro multiply768 res0, res1, res2, res3, res4, res5, res6, res7, res8, res9, res10, res11, ar0, ar1, ar2, ar3, ar4, ar5, br0, br1, br2, br3, br4, br5
    multiply768firstiteration \res0, \res1, \res2, \res3, \res4, \res5, \res6, \ar0, \br0, \br1, \br2, \br3, \br4, \br5, \res11
    multiply768iteration \res1, \res2, \res3, \res4, \res5, \res6, \res7, \ar1, \br0, \br1, \br2, \br3, \br4, \br5, \res11, \ar0
    multiply768iteration \res2, \res3, \res4, \res5, \res6, \res7, \res8, \ar2, \br0, \br1, \br2, \br3, \br4, \br5, \ar1, \ar0
    multiply768iteration \res3, \res4, \res5, \res6, \res7, \res8, \res9, \ar3, \br0, \br1, \br2, \br3, \br4, \br5, \ar1, \ar0
    multiply768iteration \res4, \res5, \res6, \res7, \res8, \res9, \res10, \ar4, \br0, \br1, \br2, \br3, \br4, \br5, \ar1, \ar0
    multiply768iteration \res5, \res6, \res7, \res8, \res9, \res10, \res11, \ar5, \br0, \br1, \br2, \br3, \br4, \br5, \ar1, \ar0
.endm

.global embedded_pairing_core_arch_aarch64_bigint_768_multiply
.type embedded_pairing_core_arch_aarch64_bigint_768_multiply, %function
.text

embedded_pairing_core_arch_aarch64_bigint_768_multiply:
    // Save registers
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!

    // Load b into {x9, x10, x11, x12, x13, x14}
    ldp x9, x10, [x2], #16
    ldp x11, x12, [x2], #16
    ldp x13, x14, [x2], #16

    // Load a into {x2, x3, x4, x5, x6, x7}
    ldp x2, x3, [x1], #16
    ldp x4, x5, [x1], #16
    ldp x6, x7, [x1], #16

    multiply768 x1, x15, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x2, x3, x4, x5, x6, x7, x9, x10, x11, x12, x13, x14

    // Store result from {x1, x15, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28}
    stp x1, x15, [x0], #16
    stp x19, x20, [x0], #16
    stp x21, x22, [x0], #16
    stp x23, x24, [x0], #16
    stp x25, x26, [x0], #16
    stp x27, x28, [x0], #16

    // Restore registers and return
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret

// Sets res := a * a
.macro square768 res0, res1, res2, res3, res4, res5, res6, res7, res8, res9, res10, res11, ar0, ar1, ar2, ar3, ar4, ar5
    adds xzr, xzr, xzr // Clear carry flag

    // Iteration i = 1
    multiply64 \res1, \res2, \ar1, \ar0

    // Iteration i = 2
    muladd64 \res2, \res0, \ar2, \ar0, \res11
    mulcarry64 \res3, \res4, \ar2, \ar1, \res0
    adcs \res4, \res4, xzr

    // Iteration i = 3
    muladd64 \res3, \res6, \ar3, \ar0, \res11
    muladdcarry64 \res4, \res0, \ar3, \ar1, \res6 \res11
    mulcarry64 \res5, \res6, \ar3, \ar2, \res0
    adcs \res6, \res6, xzr

    // Iteration i = 4
    muladd64 \res4, \res0, \ar4, \ar0, \res11
    muladdcarry64 \res5, \res8, \ar4, \ar1, \res0, \res11
    muladdcarry64 \res6, \res0, \ar4, \ar2, \res8, \res11
    mulcarry64 \res7, \res8, \ar4, \ar3, \res0
    adcs \res8, \res8, xzr

    // Iteration i = 5
    muladd64 \res5, \res10, \ar5, \ar0, \res11
    muladdcarry64 \res6, \res0, \ar5, \ar1, \res10, \res11
    muladdcarry64 \res7, \res10, \ar5, \ar2, \res0, \res11
    muladdcarry64 \res8, \res0, \ar5, \ar3, \res10, \res11
    mulcarry64 \res9, \res10, \ar5, \ar4, \res0
    adcs \res10, \res10, xzr

    add \res0, xzr, xzr

    // Double the result
    adds \res1, \res1, \res1
    adcs \res2, \res2, \res2
    adcs \res3, \res3, \res3
    adcs \res4, \res4, \res4
    adcs \res5, \res5, \res5
    adcs \res6, \res6, \res6
    adcs \res7, \res7, \res7
    adcs \res8, \res8, \res8
    adcs \res9, \res9, \res9
    adcs \res10, \res10, \res10
    adcs \res11, xzr, xzr

    // Handle the diagonal
    mul \res0, \ar0, \ar0
    umulh \ar0, \ar0, \ar0
    adds \res1, \res1, \ar0

    mul \ar0, \ar1, \ar1
    umulh \ar1, \ar1, \ar1
    adcs \res2, \res2, \ar0
    adcs \res3, \res3, \ar1

    mul \ar0, \ar2, \ar2
    umulh \ar1, \ar2, \ar2
    adcs \res4, \res4, \ar0
    adcs \res5, \res5, \ar1

    mul \ar0, \ar3, \ar3
    umulh \ar1, \ar3, \ar3
    adcs \res6, \res6, \ar0
    adcs \res7, \res7, \ar1

    mul \ar0, \ar4, \ar4
    umulh \ar1, \ar4, \ar4
    adcs \res8, \res8, \ar0
    adcs \res9, \res9, \ar1

    mul \ar0, \ar5, \ar5
    umulh \ar1, \ar5, \ar5
    adcs \res10, \res10, \ar0
    adcs \res11, \res11, \ar1
.endm

.global embedded_pairing_core_arch_aarch64_bigint_768_square
.type embedded_pairing_core_arch_aarch64_bigint_768_square, %function
.text

embedded_pairing_core_arch_aarch64_bigint_768_square:
    // Save registers
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!

    // Load a into {x2, x3, x4, x5, x6, x7}
    ldp x2, x3, [x1], #16
    ldp x4, x5, [x1], #16
    ldp x6, x7, [x1], #16

    square768 x1, x9, x10, x11, x12, x13, x14, x15, x19, x20, x21, x22, x2, x3, x4, x5, x6, x7

    // Store result from {x1, x9, x10, x11, x12, x13, x14, x15, x19, x20, x21, x22}
    stp x1, x9, [x0], #16
    stp x10, x11, [x0], #16
    stp x12, x13, [x0], #16
    stp x14, x15, [x0], #16
    stp x19, x20, [x0], #16
    stp x21, x22, [x0], #16

    // Restore registers and return
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret

.macro montgomeryreduce384iterationraw dst0, dst1, dst2, dst3, dst4, dst5, dst6, pr0, pr1, pr2, pr3, pr4, pr5, inv, u, carry, scratch
    muladd64 \dst0, \carry, \u, \pr0, \scratch
    // \dst0 is now free, so we use it for carry (along with \carry)
    muladdcarry64 \dst1, \dst0, \u, \pr1, \carry, \scratch
    muladdcarry64 \dst2, \carry, \u, \pr2, \dst0, \scratch
    muladdcarry64 \dst3, \dst0, \u, \pr3, \carry, \scratch
    muladdcarry64 \dst4, \carry, \u, \pr4, \dst0, \scratch
    muladdcarry64 \dst5, \dst0, \u, \pr5, \carry, \scratch
.endm

.macro montgomeryreduce384iteration dst0, dst1, dst2, dst3, dst4, dst5, dst6, pr0, pr1, pr2, pr3, pr4, pr5, inv, u, carry, scratch, metacarry
    mul \u, \dst0, \inv

    montgomeryreduce384iterationraw \dst0, \dst1, \dst2, \dst3, \dst4, \dst5, \dst6, \pr0, \pr1, \pr2, \pr3, \pr4, \pr5, \inv, \u, \carry, \scratch
    adcs \dst0, \dst0, xzr
    // Now \dst0 has the output carry

    // Set carry flag to meta-carry
    subs xzr, \metacarry, #1

    // Now add metacarry and derive the new one
    adcs \dst6, \dst6, \dst0
    adcs \metacarry, xzr, xzr
.endm

.macro montgomeryreduce384 dst0, dst1, dst2, dst3, dst4, dst5, dst6, dst7, dst8, dst9, dst10, dst11, pr0, pr1, pr2, pr3, pr4, pr5, inv, u, carry, scratch
    // Iteration 0
    mul \u, \dst0, \inv
    montgomeryreduce384iterationraw \dst0, \dst1, \dst2, \dst3, \dst4, \dst5, \dst6, \pr0, \pr1, \pr2, \pr3, \pr4, \pr5, \inv, \u, \carry, \scratch
    adcs \dst6, \dst6, \dst0
    // Now \dst0 is never used by any future iterations, so we can use it as metacarry
    adcs \dst0, xzr, xzr

    // Iterations 1 - 4
    montgomeryreduce384iteration \dst1, \dst2, \dst3, \dst4, \dst5, \dst6, \dst7, \pr0, \pr1, \pr2, \pr3, \pr4, \pr5, \inv, \u, \carry, \scratch, \dst0
    montgomeryreduce384iteration \dst2, \dst3, \dst4, \dst5, \dst6, \dst7, \dst8, \pr0, \pr1, \pr2, \pr3, \pr4, \pr5, \inv, \u, \carry, \scratch, \dst0
    montgomeryreduce384iteration \dst3, \dst4, \dst5, \dst6, \dst7, \dst8, \dst9, \pr0, \pr1, \pr2, \pr3, \pr4, \pr5, \inv, \u, \carry, \scratch, \dst0
    montgomeryreduce384iteration \dst4, \dst5, \dst6, \dst7, \dst8, \dst9, \dst10, \pr0, \pr1, \pr2, \pr3, \pr4, \pr5, \inv, \u, \carry, \scratch, \dst0

    // Iteration 5
    mul \u, \dst5, \inv
    montgomeryreduce384iterationraw \dst5, \dst6, \dst7, \dst8, \dst9, \dst10, \dst11, \pr0, \pr1, \pr2, \pr3, \pr4, \pr5, \inv, \u, \carry, \scratch
    adcs \dst5, \dst5, xzr
    subs xzr, \dst0, #1
    adcs \dst11, \dst11, \dst5
.endm

.global embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce
.type embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce, %function
.text

embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce:
    // Save registers
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!

    // Load p into {x19, x20, x21, x22, x23, x24}
    ldp x19, x20, [x2], #16
    ldp x21, x22, [x2], #16
    ldp x23, x24, [x2], #16

    // Load a into {x2, x4, x5, x6, x7, x9, x10, x11, x12, x13, x14, x15}
    ldp x2, x4, [x1], #16
    ldp x5, x6, [x1], #16
    ldp x7, x9, [x1], #16
    ldp x10, x11, [x1], #16
    ldp x12, x13, [x1], #16
    ldp x14, x15, [x1], #16

    // Do the Montgomery Reduction
    montgomeryreduce384 x2, x4, x5, x6, x7, x9, x10, x11, x12, x13, x14, x15, x19, x20, x21, x22, x23, x24, x3, x1, x25, x26

    // Perform final subtraction: result is in {x10, x11, x12, x13, x14, x15}
    cmp x15, x24
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_copy
    cmp x14, x23
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_copy
    cmp x13, x22
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_copy
    cmp x12, x21
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_copy
    cmp x11, x20
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_copy
    cmp x10, x19
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_copy

embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_subtract:
    subs x10, x10, x19
    sbcs x11, x11, x20
    sbcs x12, x12, x21
    sbcs x13, x13, x22
    sbcs x14, x14, x23
    sbcs x15, x15, x24

embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce_final_copy:
    // Store result from {x10, x11, x12, x13, x14, x15}
    stp x10, x11, [x0], #16
    stp x12, x13, [x0], #16
    stp x14, x15, [x0], #16

    // Restore registers and return
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret

.global embedded_pairing_core_arch_aarch64_fpbase_384_multiply
.type embedded_pairing_core_arch_aarch64_fpbase_384_multiply, %function
.text

embedded_pairing_core_arch_aarch64_fpbase_384_multiply:
    // Save registers
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!

    // Save p and inv_word
    stp x3, x4, [sp, #-16]!

    // Load b into {x9, x10, x11, x12, x13, x14}
    ldp x9, x10, [x2], #16
    ldp x11, x12, [x2], #16
    ldp x13, x14, [x2], #16

    // Load a into {x2, x3, x4, x5, x6, x7}
    ldp x2, x3, [x1], #16
    ldp x4, x5, [x1], #16
    ldp x6, x7, [x1], #16

    multiply768 x1, x15, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x2, x3, x4, x5, x6, x7, x9, x10, x11, x12, x13, x14

    // Restore p and inv_word
    ldp x2, x3, [sp], #16

    // Load p into {x9, x10, x11, x12, x13, x14}
    ldp x9, x10, [x2], #16
    ldp x11, x12, [x2], #16
    ldp x13, x14, [x2], #16

    // Do Montgomery Reduction
    montgomeryreduce384 x1, x15, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x9, x10, x11, x12, x13, x14, x3, x2, x4, x5

    // Perform final subraction: result is in {x23, x24, x25, x26, x27, x28}
    cmp x28, x14
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_copy
    cmp x27, x13
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_copy
    cmp x26, x12
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_copy
    cmp x25, x11
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_copy
    cmp x24, x10
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_copy
    cmp x23, x9
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_copy

embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_subtract:
    subs x23, x23, x9
    sbcs x24, x24, x10
    sbcs x25, x25, x11
    sbcs x26, x26, x12
    sbcs x27, x27, x13
    sbcs x28, x28, x14

embedded_pairing_core_arch_aarch64_fpbase_384_multiply_final_copy:
    // Store result from {x23, x24, x25, x26, x27, x28}
    stp x23, x24, [x0], #16
    stp x25, x26, [x0], #16
    stp x27, x28, [x0], #16

    // Restore registers and return
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret

.global embedded_pairing_core_arch_aarch64_fpbase_384_square
.type embedded_pairing_core_arch_aarch64_fpbase_384_square, %function
.text

embedded_pairing_core_arch_aarch64_fpbase_384_square:
    // Save registers
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!

    // Save p and inv_word
    stp x2, x3, [sp, #-16]!

    // Load a into {x2, x3, x4, x5, x6, x7}
    ldp x2, x3, [x1], #16
    ldp x4, x5, [x1], #16
    ldp x6, x7, [x1], #16

    square768 x1, x9, x10, x11, x12, x13, x14, x15, x19, x20, x21, x22, x2, x3, x4, x5, x6, x7

    // Restore p and inv_word
    ldp x2, x3, [sp], #16

    // Load p into {x4, x5, x6, x7, x23, x24}
    ldp x4, x5, [x2], #16
    ldp x6, x7, [x2], #16
    ldp x23, x24, [x2], #16

    montgomeryreduce384 x1, x9, x10, x11, x12, x13, x14, x15, x19, x20, x21, x22, x4, x5, x6, x7, x23, x24, x3, x2, x25, x26

    // Perform final subtraction: result is in {x14, x15, x19, x20, x21, x22}
    cmp x22, x24
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_square_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_square_final_copy
    cmp x21, x23
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_square_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_square_final_copy
    cmp x20, x7
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_square_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_square_final_copy
    cmp x19, x6
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_square_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_square_final_copy
    cmp x15, x5
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_square_final_subtract
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_square_final_copy
    cmp x14, x4
    b.lo embedded_pairing_core_arch_aarch64_fpbase_384_square_final_copy

embedded_pairing_core_arch_aarch64_fpbase_384_square_final_subtract:
    subs x14, x14, x4
    sbcs x15, x15, x5
    sbcs x19, x19, x6
    sbcs x20, x20, x7
    sbcs x21, x21, x23
    sbcs x22, x22, x24

embedded_pairing_core_arch_aarch64_fpbase_384_square_final_copy:
    // Store result from {x14, x15, x19, x20, x21, x22}
    stp x14, x15, [x0], #16
    stp x19, x20, [x0], #16
    stp x21, x22, [x0], #16

    // Restore registers and return
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret
