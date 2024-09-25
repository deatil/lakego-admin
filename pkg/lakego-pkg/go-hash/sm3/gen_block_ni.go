// Not used yet!!!
// go run gen_block_ni.go

//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

//SM3PARTW1 <Vd>.4S, <Vn>.4S, <Vm>.4S
func sm3partw1(Vd, Vn, Vm byte) uint32 {
	inst := uint32(0xce60c000) | uint32(Vd&0x1f) | uint32(Vn&0x1f)<<5 | (uint32(Vm&0x1f) << 16)
	// return bits.ReverseBytes32(inst)
	return inst
}

//SM3PARTW2 <Vd>.4S, <Vn>.4S, <Vm>.4S
func sm3partw2(Vd, Vn, Vm byte) uint32 {
	inst := uint32(0xce60c400) | uint32(Vd&0x1f) | uint32(Vn&0x1f)<<5 | (uint32(Vm&0x1f) << 16)
	// return bits.ReverseBytes32(inst)
	return inst
}

//SM3SS1 <Vd>.4S, <Vn>.4S, <Vm>.4S, <Va>.4S
func sm3ss1(Vd, Vn, Vm, Va byte) uint32 {
	inst := uint32(0xce400000) | uint32(Vd&0x1f) | uint32(Vn&0x1f)<<5 | uint32(Va&0x1f)<<10 | uint32(Vm&0x1f)<<16
	// return bits.ReverseBytes32(inst)
	return inst
}

//SM3TT1A <Vd>.4S, <Vn>.4S, <Vm>.S[<imm2>]
func sm3tt1a(Vd, Vn, Vm, imm2 byte) uint32 {
	inst := uint32(0xce408000) | uint32(Vd&0x1f) | uint32(Vn&0x1f)<<5 | uint32(imm2&0x3)<<12 | uint32(Vm&0x1f)<<16
	// return bits.ReverseBytes32(inst)
	return inst
}

//SM3TT1B <Vd>.4S, <Vn>.4S, <Vm>.S[<imm2>]
func sm3tt1b(Vd, Vn, Vm, imm2 byte) uint32 {
	inst := uint32(0xce408400) | uint32(Vd&0x1f) | uint32(Vn&0x1f)<<5 | uint32(imm2&0x3)<<12 | uint32(Vm&0x1f)<<16
	// return bits.ReverseBytes32(inst)
	return inst
}

//SM3TT2A <Vd>.4S, <Vn>.4S, <Vm>.S[<imm2>]
func sm3tt2a(Vd, Vn, Vm, imm2 byte) uint32 {
	inst := uint32(0xce408800) | uint32(Vd&0x1f) | uint32(Vn&0x1f)<<5 | uint32(imm2&0x3)<<12 | uint32(Vm&0x1f)<<16
	// return bits.ReverseBytes32(inst)
	return inst
}

//SM3TT2B <Vd>.4S, <Vn>.4S, <Vm>.S[<imm2>]
func sm3tt2b(Vd, Vn, Vm, imm2 byte) uint32 {
	inst := uint32(0xce408c00) | uint32(Vd&0x1f) | uint32(Vn&0x1f)<<5 | uint32(imm2&0x3)<<12 | uint32(Vm&0x1f)<<16
	// return bits.ReverseBytes32(inst)
	return inst
}

// Used v5 as temp register
func roundA(buf *bytes.Buffer, i, t0, t1, st1, st2, w, wt byte) {
	fmt.Fprintf(buf, "\tWORD $0x%08x           //SM3SS1 V%d.4S, V%d.4S, V%d.4S, V%d.4S\n", sm3ss1(5, st1, t0, st2), 5, st1, t0, st2)
	fmt.Fprintf(buf, "\tVSHL $1, V%d.S4, V%d.S4\n", t0, t1)
	fmt.Fprintf(buf, "\tVSRI $31, V%d.S4, V%d.S4\n", t0, t1)
	fmt.Fprintf(buf, "\tWORD $0x%08x           //SM3TT1A V%dd.4S, V%d.4S, V%d.S, %d\n", sm3tt1a(st1, 5, wt, i), st1, 5, wt, i)
	fmt.Fprintf(buf, "\tWORD $0x%08x           //SM3TT2A V%dd.4S, V%d.4S, V%d.S, %d\n", sm3tt2a(st2, 5, w, i), st2, 5, w, i)
}

// Used v5 as temp register
func roundB(buf *bytes.Buffer, i, t0, t1, st1, st2, w, wt byte) {
	fmt.Fprintf(buf, "\tWORD $0x%08x           //SM3SS1 V%d.4S, V%d.4S, V%d.4S, V%d.4S\n", sm3ss1(5, st1, t0, st2), 5, st1, t0, st2)
	fmt.Fprintf(buf, "\tVSHL $1, V%d.S4, V%d.S4\n", t0, t1)
	fmt.Fprintf(buf, "\tVSRI $31, V%d.S4, V%d.S4\n", t0, t1)
	fmt.Fprintf(buf, "\tWORD $0x%08x           //SM3TT1B V%dd.4S, V%d.4S, V%d.S, %d\n", sm3tt1b(st1, 5, wt, i), st1, 5, wt, i)
	fmt.Fprintf(buf, "\tWORD $0x%08x           //SM3TT2B V%dd.4S, V%d.4S, V%d.S, %d\n", sm3tt2b(st2, 5, w, i), st2, 5, w, i)
}

// Compress 4 words and generate 4 words, use v6, v7, v10 as temp registers
// s4, used to store next 4 words
// s0, W(4i) W(4i+1) W(4i+2) W(4i+3)
// s1, W(4i+4) W(4i+5) W(4i+6) W(4i+7)
// s2, W(4i+8) W(4i+9) W(4i+10) W(4i+11)
// s3, W(4i+12) W(4i+13) W(4i+14) W(4i+15)
// t, t constant
// st1, st2, sm3 state
func qroundA(buf *bytes.Buffer, t0, t1, st1, st2, s0, s1, s2, s3, s4 byte) {
	fmt.Fprintf(buf, "\t// Extension\n")
	fmt.Fprintf(buf, "\tVEXT $12, V%d.B16, V%d.B16, V%d.B16\n", s2, s1, s4)
	fmt.Fprintf(buf, "\tVEXT $12, V%d.B16, V%d.B16, V%d.B16\n", s1, s0, 6)
	fmt.Fprintf(buf, "\tVEXT $8, V%d.B16, V%d.B16, V%d.B16\n", s3, s2, 7)
	fmt.Fprintf(buf, "\tWORD $0x%08x          //SM3PARTW1 V%d.4S, V%d.4S, V%d.4S\n", sm3partw1(s4, s0, s3), s4, s0, s3)
	fmt.Fprintf(buf, "\tWORD $0x%08x          //SM3PARTW2 V%d.4S, V%d.4S, V%d.4S\n", sm3partw2(s4, 7, 6), s4, 7, 6)
	fmt.Fprintf(buf, "\tVEOR V%d.B16, V%d.B16, V10.B16\n", s1, s0)
	fmt.Fprintf(buf, "\t// Compression\n")
	roundA(buf, 0, t0, t1, st1, st2, s0, 10)
	roundA(buf, 1, t1, t0, st1, st2, s0, 10)
	roundA(buf, 2, t0, t1, st1, st2, s0, 10)
	roundA(buf, 3, t1, t0, st1, st2, s0, 10)
	fmt.Fprintf(buf, "\n")
}

// Used v6, v7, v10 as temp registers
func qroundB(buf *bytes.Buffer, t0, t1, st1, st2, s0, s1, s2, s3, s4 byte) {
	if s4 != 0xff {
		fmt.Fprintf(buf, "\t// Extension\n")
		fmt.Fprintf(buf, "\tVEXT $12, V%d.B16, V%d.B16, V%d.B16\n", s2, s1, s4)
		fmt.Fprintf(buf, "\tVEXT $12, V%d.B16, V%d.B16, V%d.B16\n", s1, s0, 6)
		fmt.Fprintf(buf, "\tVEXT $8, V%d.B16, V%d.B16, V%d.B16\n", s3, s2, 7)
		fmt.Fprintf(buf, "\tWORD $0x%08x          //SM3PARTW1 V%d.4S, V%d.4S, V%d.4S\n", sm3partw1(s4, s0, s3), s4, s0, s3)
		fmt.Fprintf(buf, "\tWORD $0x%08x          //SM3PARTW2 V%d.4S, V%d.4S, V%d.4S\n", sm3partw2(s4, 7, 6), s4, 7, 6)
	}
	fmt.Fprintf(buf, "\tVEOR V%d.B16, V%d.B16, V10.B16\n", s1, s0)
	fmt.Fprintf(buf, "\t// Compression\n")
	roundB(buf, 0, t0, t1, st1, st2, s0, 10)
	roundB(buf, 1, t1, t0, st1, st2, s0, 10)
	roundB(buf, 2, t0, t1, st1, st2, s0, 10)
	roundB(buf, 3, t1, t0, st1, st2, s0, 10)
	fmt.Fprintf(buf, "\n")
}

func main() {
	buf := new(bytes.Buffer)
	fmt.Fprint(buf, `
// Generated by gen_sm3block_ni.go. DO NOT EDIT.
//go:build !purego

#include "textflag.h"

// func blockSM3NI(h []uint32, p []byte, t []uint32)
TEXT ·blockSM3NI(SB), 0, $0
	MOVD	h_base+0(FP), R0                           // Hash value first address
	MOVD	p_base+24(FP), R1                          // message first address
	MOVD	p_len+32(FP), R3                           // message length
	MOVD	t_base+48(FP), R2                          // t constants first address

	VLD1 (R0), [V8.S4, V9.S4]                          // load h(a,b,c,d,e,f,g,h)
	VREV64  V8.S4, V8.S4
	VEXT $8, V8.B16, V8.B16, V8.B16
	VREV64  V9.S4, V9.S4
	VEXT $8, V9.B16, V9.B16, V9.B16
	LDPW	(0*8)(R2), (R5, R6)                        // load t constants

blockloop:
	VLD1.P	64(R1), [V0.B16, V1.B16, V2.B16, V3.B16]    // load 64bytes message
	VMOV	V8.B16, V15.B16                             // backup: V8 h(dcba)
	VMOV	V9.B16, V16.B16                             // backup: V9 h(hgfe)
	VREV32	V0.B16, V0.B16                              // prepare for using message in Byte format
	VREV32	V1.B16, V1.B16
	VREV32	V2.B16, V2.B16
	VREV32	V3.B16, V3.B16
	// first 16 rounds
	VMOV R5, V11.S[3]
`[1:])
	qroundA(buf, 11, 12, 8, 9, 0, 1, 2, 3, 4)
	qroundA(buf, 11, 12, 8, 9, 1, 2, 3, 4, 0)
	qroundA(buf, 11, 12, 8, 9, 2, 3, 4, 0, 1)
	qroundA(buf, 11, 12, 8, 9, 3, 4, 0, 1, 2)

	fmt.Fprintf(buf, "\t// second 48 rounds\n")
	fmt.Fprintf(buf, "\tVMOV R6, V11.S[3]\n")
	qroundB(buf, 11, 12, 8, 9, 4, 0, 1, 2, 3)
	qroundB(buf, 11, 12, 8, 9, 0, 1, 2, 3, 4)
	qroundB(buf, 11, 12, 8, 9, 1, 2, 3, 4, 0)
	qroundB(buf, 11, 12, 8, 9, 2, 3, 4, 0, 1)
	qroundB(buf, 11, 12, 8, 9, 3, 4, 0, 1, 2)
	qroundB(buf, 11, 12, 8, 9, 4, 0, 1, 2, 3)
	qroundB(buf, 11, 12, 8, 9, 0, 1, 2, 3, 4)
	qroundB(buf, 11, 12, 8, 9, 1, 2, 3, 4, 0)
	qroundB(buf, 11, 12, 8, 9, 2, 3, 4, 0, 1)
	qroundB(buf, 11, 12, 8, 9, 3, 4, 0xff, 0xff, 0xff)
	qroundB(buf, 11, 12, 8, 9, 4, 0, 0xff, 0xff, 0xff)
	qroundB(buf, 11, 12, 8, 9, 0, 1, 0xff, 0xff, 0xff)

	fmt.Fprint(buf, `
	SUB	$64, R3, R3                                  // message length - 64bytes, then compare with 64bytes
	VEOR	V8.B16, V15.B16, V8.B16
	VEOR	V9.B16, V16.B16, V9.B16
	CBNZ	R3, blockloop

sm3ret:
	VREV64  V8.S4, V8.S4
	VEXT $8, V8.B16, V8.B16, V8.B16
	VREV64  V9.S4, V9.S4
	VEXT $8, V9.B16, V9.B16, V9.B16
	VST1	[V8.S4, V9.S4], (R0)                       // store hash value H
	RET

`[1:])
	src := buf.Bytes()
	// fmt.Println(string(src))

	err := os.WriteFile("block_ni_arm64.s", src, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
