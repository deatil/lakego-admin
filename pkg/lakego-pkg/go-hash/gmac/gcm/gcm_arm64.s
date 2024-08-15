//go:build arm64 && !purego && (!gccgo || go1.18)
// +build arm64
// +build !purego
// +build !gccgo go1.18

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

#define B0 V0
#define B1 V1
#define B2 V2
#define B3 V3
#define B4 V4
#define B5 V5
#define B6 V6
#define B7 V7

#define ACC0 V8
#define ACC1 V9
#define ACCM V10

#define T0 V11
#define T1 V12
#define T2 V13
#define T3 V14

#define POLY V15
#define ZERO V16
#define INC V17
#define CTR V18

#define K0 V19
#define K1 V20
#define K2 V21
#define K3 V22
#define K4 V23
#define K5 V24
#define K6 V25
#define K7 V26
#define K8 V27
#define K9 V28
#define K10 V29
#define K11 V30
#define KLAST V31

#define reduce() \
    VEOR	ACC0.B16, ACCM.B16, ACCM.B16     \
    VEOR	ACC1.B16, ACCM.B16, ACCM.B16     \
    VEXT	$8, ZERO.B16, ACCM.B16, T0.B16   \
    VEXT	$8, ACCM.B16, ZERO.B16, ACCM.B16 \
    VEOR	ACCM.B16, ACC0.B16, ACC0.B16     \
    VEOR	T0.B16, ACC1.B16, ACC1.B16       \
    VPMULL	POLY.D1, ACC0.D1, T0.Q1          \
    VEXT	$8, ACC0.B16, ACC0.B16, ACC0.B16 \
    VEOR	T0.B16, ACC0.B16, ACC0.B16       \
    VPMULL	POLY.D1, ACC0.D1, T0.Q1          \
    VEOR	T0.B16, ACC1.B16, ACC1.B16       \
    VEXT	$8, ACC1.B16, ACC1.B16, ACC1.B16 \
    VEOR	ACC1.B16, ACC0.B16, ACC0.B16     \

// func gcmFinish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)
TEXT ·_gcmFinish(SB),NOSPLIT,$0
#define pTbl R0
#define tMsk R1
#define tPtr R2
#define plen R3
#define dlen R4

    MOVD	$0xC2, R1
    LSL	$56, R1
    MOVD	$1, R0
    VMOV	R1, POLY.D[0]
    VMOV	R0, POLY.D[1]
    VEOR	ZERO.B16, ZERO.B16, ZERO.B16

    MOVD	productTable+0(FP), pTbl
    MOVD	tagMask+8(FP), tMsk
    MOVD	T+16(FP), tPtr
    MOVD	pLen+24(FP), plen
    MOVD	dLen+32(FP), dlen

    VLD1	(tPtr), [ACC0.B16]
    VLD1	(tMsk), [B1.B16]

    LSL	$3, plen
    LSL	$3, dlen

    VMOV	dlen, B0.D[0]
    VMOV	plen, B0.D[1]

    ADD	$14*16, pTbl
    VLD1.P	(pTbl), [T1.B16, T2.B16]

    VEOR	ACC0.B16, B0.B16, B0.B16

    VEXT	$8, B0.B16, B0.B16, T0.B16
    VEOR	B0.B16, T0.B16, T0.B16
    VPMULL	B0.D1, T1.D1, ACC1.Q1
    VPMULL2	B0.D2, T1.D2, ACC0.Q1
    VPMULL	T0.D1, T2.D1, ACCM.Q1

    reduce()

    VREV64	ACC0.B16, ACC0.B16
    VEOR	B1.B16, ACC0.B16, ACC0.B16

    VST1	[ACC0.B16], (tPtr)
    RET
#undef pTbl
#undef tMsk
#undef tPtr
#undef plen
#undef dlen

// func gcmInit(productTable *[256]byte, ks []uint32)
TEXT ·_gcmInit(SB),NOSPLIT,$0
#define pTbl R0
#define KS R1
#define I R3
    MOVD	productTable+0(FP), pTbl
    MOVD	ks_base+8(FP), KS

    MOVD	$0xC2, I
    LSL	$56, I
    VMOV	I, POLY.D[0]
    MOVD	$1, I
    VMOV	I, POLY.D[1]
    VEOR	ZERO.B16, ZERO.B16, ZERO.B16

    VLD1    (KS), [B0.B16]

    VREV64	B0.B16, B0.B16


    // Multiply by 2 modulo P
    VMOV	B0.D[0], I
    ASR	$63, I
    VMOV	I, T1.D[0]
    VMOV	I, T1.D[1]
    VAND	POLY.B16, T1.B16, T1.B16
    VUSHR	$63, B0.D2, T2.D2
    VEXT	$8, ZERO.B16, T2.B16, T2.B16
    VSHL	$1, B0.D2, B0.D2
    VEOR	T1.B16, B0.B16, B0.B16
    VEOR	T2.B16, B0.B16, B0.B16 // Can avoid this when VSLI is available

    // Karatsuba pre-computation
    VEXT	$8, B0.B16, B0.B16, B1.B16
    VEOR	B0.B16, B1.B16, B1.B16

    ADD	$14*16, pTbl
    VST1	[B0.B16, B1.B16], (pTbl)
    SUB	$2*16, pTbl

    VMOV	B0.B16, B2.B16
    VMOV	B1.B16, B3.B16

    MOVD	$7, I

initLoop:
    // Compute powers of H
    SUBS	$1, I

    VPMULL	B0.D1, B2.D1, T1.Q1
    VPMULL2	B0.D2, B2.D2, T0.Q1
    VPMULL	B1.D1, B3.D1, T2.Q1
    VEOR	T0.B16, T2.B16, T2.B16
    VEOR	T1.B16, T2.B16, T2.B16
    VEXT	$8, ZERO.B16, T2.B16, T3.B16
    VEXT	$8, T2.B16, ZERO.B16, T2.B16
    VEOR	T2.B16, T0.B16, T0.B16
    VEOR	T3.B16, T1.B16, T1.B16
    VPMULL	POLY.D1, T0.D1, T2.Q1
    VEXT	$8, T0.B16, T0.B16, T0.B16
    VEOR	T2.B16, T0.B16, T0.B16
    VPMULL	POLY.D1, T0.D1, T2.Q1
    VEXT	$8, T0.B16, T0.B16, T0.B16
    VEOR	T2.B16, T0.B16, T0.B16
    VEOR	T1.B16, T0.B16, B2.B16
    VMOV	B2.B16, B3.B16
    VEXT	$8, B2.B16, B2.B16, B2.B16
    VEOR	B2.B16, B3.B16, B3.B16

    VST1	[B2.B16, B3.B16], (pTbl)
    SUB	$2*16, pTbl

    BNE	initLoop
    RET
#undef I
#undef KS
#undef pTbl

// func gcmData(productTable *[256]byte, data []byte, T *[16]byte)
TEXT ·_gcmData(SB),NOSPLIT,$0
#define pTbl R0
#define aut R1
#define tPtr R2
#define autLen R3
#define H0 R4
#define pTblSave R5

#define mulRound(X) \
    VLD1.P	32(pTbl), [T1.B16, T2.B16] \
    VREV64	X.B16, X.B16               \
    VEXT	$8, X.B16, X.B16, T0.B16   \
    VEOR	X.B16, T0.B16, T0.B16      \
    VPMULL	X.D1, T1.D1, T3.Q1         \
    VEOR	T3.B16, ACC1.B16, ACC1.B16 \
    VPMULL2	X.D2, T1.D2, T3.Q1         \
    VEOR	T3.B16, ACC0.B16, ACC0.B16 \
    VPMULL	T0.D1, T2.D1, T3.Q1        \
    VEOR	T3.B16, ACCM.B16, ACCM.B16

    MOVD	productTable+0(FP), pTbl
    MOVD	data_base+8(FP), aut
    MOVD	data_len+16(FP), autLen
    MOVD	T+32(FP), tPtr

    VLD1	(tPtr), [ACC0.B16]
    CBZ	autLen, dataBail

    MOVD	$0xC2, H0
    LSL	$56, H0
    VMOV	H0, POLY.D[0]
    MOVD	$1, H0
    VMOV	H0, POLY.D[1]
    VEOR	ZERO.B16, ZERO.B16, ZERO.B16
    MOVD	pTbl, pTblSave

    CMP	$13, autLen
    BEQ	dataTLS
    CMP	$128, autLen
    BLT	startSinglesLoop
    B	octetsLoop

dataTLS:
    ADD	$14*16, pTbl
    VLD1.P	(pTbl), [T1.B16, T2.B16]
    VEOR	B0.B16, B0.B16, B0.B16

    MOVD	(aut), H0
    VMOV	H0, B0.D[0]
    MOVW	8(aut), H0
    VMOV	H0, B0.S[2]
    MOVB	12(aut), H0
    VMOV	H0, B0.B[12]

    MOVD	$0, autLen
    B	dataMul

octetsLoop:
        CMP	$128, autLen
        BLT	startSinglesLoop
        SUB	$128, autLen

        VLD1.P	32(aut), [B0.B16, B1.B16]

        VLD1.P	32(pTbl), [T1.B16, T2.B16]
        VREV64	B0.B16, B0.B16
        VEOR	ACC0.B16, B0.B16, B0.B16
        VEXT	$8, B0.B16, B0.B16, T0.B16
        VEOR	B0.B16, T0.B16, T0.B16
        VPMULL	B0.D1, T1.D1, ACC1.Q1
        VPMULL2	B0.D2, T1.D2, ACC0.Q1
        VPMULL	T0.D1, T2.D1, ACCM.Q1

        mulRound(B1)
        VLD1.P  32(aut), [B2.B16, B3.B16]
        mulRound(B2)
        mulRound(B3)
        VLD1.P  32(aut), [B4.B16, B5.B16]
        mulRound(B4)
        mulRound(B5)
        VLD1.P  32(aut), [B6.B16, B7.B16]
        mulRound(B6)
        mulRound(B7)

        MOVD	pTblSave, pTbl
        reduce()
    B	octetsLoop

startSinglesLoop:

    ADD	$14*16, pTbl
    VLD1.P	(pTbl), [T1.B16, T2.B16]

singlesLoop:

        CMP	$16, autLen
        BLT	dataEnd
        SUB	$16, autLen

        VLD1.P	16(aut), [B0.B16]
dataMul:
        VREV64	B0.B16, B0.B16
        VEOR	ACC0.B16, B0.B16, B0.B16

        VEXT	$8, B0.B16, B0.B16, T0.B16
        VEOR	B0.B16, T0.B16, T0.B16
        VPMULL	B0.D1, T1.D1, ACC1.Q1
        VPMULL2	B0.D2, T1.D2, ACC0.Q1
        VPMULL	T0.D1, T2.D1, ACCM.Q1

        reduce()

    B	singlesLoop

dataEnd:

    CBZ	autLen, dataBail
    VEOR	B0.B16, B0.B16, B0.B16
    ADD	autLen, aut

dataLoadLoop:
        MOVB.W	-1(aut), H0
        VEXT	$15, B0.B16, ZERO.B16, B0.B16
        VMOV	H0, B0.B[0]
        SUBS	$1, autLen
        BNE	dataLoadLoop
    B	dataMul

dataBail:
    VST1	[ACC0.B16], (tPtr)
    RET

#undef pTbl
#undef aut
#undef tPtr
#undef autLen
#undef H0
#undef pTblSave
