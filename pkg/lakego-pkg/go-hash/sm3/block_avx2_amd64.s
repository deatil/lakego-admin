//go:build !purego

#include "textflag.h"

#include "const_asm.s"

// Definitions for AVX2 version

// xorm (mem), reg
// Xor reg to mem using reg-mem xor and store
#define xorm(P1, P2) \
	XORL P2, P1; \
	MOVL P1, P2

#define XDWORD0 Y4
#define XDWORD1 Y5
#define XDWORD2 Y6
#define XDWORD3 Y7

#define XWORD0 X4
#define XWORD1 X5
#define XWORD2 X6
#define XWORD3 X7

#define XTMP0 Y0
#define XTMP1 Y1
#define XTMP2 Y2
#define XTMP3 Y3
#define XTMP4 Y8

#define XFER  Y9
#define R08_SHUFFLE_MASK Y10

#define BYTE_FLIP_MASK 	Y13 // mask to convert LE -> BE
#define X_BYTE_FLIP_MASK X13

#define NUM_BYTES DX
#define INP	DI

#define CTX SI // Beginning of digest in memory (a, b, c, ... , h)

#define a AX
#define b BX
#define c CX
#define d DX
#define e R8
#define f R9
#define g R10
#define h R11

#define y0 R12
#define y1 R13
#define y2 R14

// Offsets
#define XFER_SIZE 4*64*4
#define INP_END_SIZE 8

#define _XFER 0
#define _INP_END _XFER + XFER_SIZE
#define STACK_SIZE _INP_END + INP_END_SIZE

#define P0(tt2, tmp, out) \
	RORXL    $23, tt2, tmp;                        \
	RORXL    $15, tt2, out;                        \
	XORL     tmp, out;                             \
	XORL     tt2, out

// For rounds [0 - 16)
#define ROUND_AND_SCHED_N_0_0(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12, RORXL is BMI2 instr
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPALIGNR $12, XDWORD0, XDWORD1, XTMP0;     \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSLLD   $7, XTMP0, XTMP1;                 \ // XTMP1 = W[-13] << 7 = {w6<<7,w5<<7,w4<<7,w3<<7}
	ADDL     (disp + 0*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 0*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	VPSRLD   $(32-7), XTMP0, XTMP0;            \ // XTMP0 = W[-13] >> 25 = {w6>>25,w5>>25,w4>>25,w3>>25}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, h;                             \
	XORL     b, h;                             \
	VPOR     XTMP0, XTMP1, XTMP1;              \ // XTMP1 = W[-13] rol 7
	XORL     c, h;                             \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     e, y1;                            \
	VPALIGNR $8, XDWORD2, XDWORD3, XTMP0;      \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	VPXOR   XTMP1, XTMP0, XTMP0;               \ // XTMP0 = W[-6] ^ (W[-13] rol 7)
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPALIGNR $12, XDWORD1, XDWORD2, XTMP1;     \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
	P0(y2, y0, d);                             \
	VPXOR XDWORD0, XTMP1, XTMP1;               \ // XTMP1 = W[-9] ^ W[-16]

#define ROUND_AND_SCHED_N_0_1(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPSHUFD $0xA5, XDWORD3, XTMP2;             \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSRLQ  $17, XTMP2, XTMP2;                 \ // XTMP2 = W[-3] rol 15 {xBxA}
	ADDL     (disp + 1*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W
	ADDL     (disp + 1*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	VPXOR   XTMP1, XTMP2, XTMP2;               \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxxA}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, h;                             \
	XORL     b, h;                             \
	VPSHUFD $0x00, XTMP2, XTMP2;               \ // XTMP2 = {AAAA}
	XORL     c, h;                             \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     e, y1;                            \ 
	XORL     f, y1;                            \
	VPSRLQ  $17, XTMP2, XTMP3;                 \ // XTMP3 = XTMP2 rol 15 {xxxA}
	XORL     g, y1;                            \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPSRLQ  $9, XTMP2, XTMP4;                  \ // XTMP4 = XTMP2 rol 23 {xxxA}
	P0(y2, y0, d);                             \
	VPXOR    XTMP2, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 23 {xxxA})

#define ROUND_AND_SCHED_N_0_2(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPXOR    XTMP4, XTMP3, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 15 {xxxA}) ^ (XTMP2 rol 23 {xxxA})
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 2*4)(SP), y2;             \ // y2 = SS1 + W
	VPXOR    XTMP4, XTMP0, XTMP2;              \ // XTMP2 = {..., ..., ..., W[0]}
	ADDL     h, y2;                            \ // y2 = h + SS1 + W
	ADDL     (disp + 2*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	VPALIGNR $4, XDWORD3, XTMP2, XTMP3;        \ // XTMP3 = {W[0], w15, w14, w13}
	MOVL     a, h;                             \
	XORL     b, h;                             \
	XORL     c, h;                             \
	VPSLLD   $15, XTMP3, XTMP4;                \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     e, y1;                            \
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	VPSRLD   $(32-15), XTMP3, XTMP3;           \
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPOR     XTMP3, XTMP4, XTMP4;              \ // XTMP4 = (W[-3] rol 15) {DCBA}
	P0(y2, y0, d);                             \
	VPXOR   XTMP1, XTMP4, XTMP4;               \ // XTMP4 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {DCBA}

#define ROUND_AND_SCHED_N_0_3(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPSLLD   $15, XTMP4, XTMP2;                \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSRLD   $(32-15), XTMP4, XTMP3;           \
	ADDL     (disp + 3*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 3*4 + 32)(SP), y0;        \ // y2 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	VPOR     XTMP3, XTMP2, XTMP3;              \ // XTMP3 = XTMP4 rol 15 {DCBA}
	MOVL     a, h;                             \
	XORL     b, h;                             \
	XORL     c, h;                             \
	VPSHUFB  R08_SHUFFLE_MASK, XTMP3, XTMP1;   \ // XTMP1 = XTMP4 rol 23 {DCBA}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     e, y1;                            \
	XORL     f, y1;                            \
	XORL     g, y1;                            \
	VPXOR    XTMP3, XTMP4, XTMP3;              \ // XTMP3 = XTMP4 ^ (XTMP4 rol 15 {DCBA})
	ADDL     y1, y2;                           \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPXOR    XTMP3, XTMP1, XTMP1;              \ // XTMP1 = XTMP4 ^ (XTMP4 rol 15 {DCBA}) ^ (XTMP4 rol 23 {DCBA})
	P0(y2, y0, d);                             \
	VPXOR    XTMP1, XTMP0, XDWORD0;            \ // XDWORD0 = {W[3], W[2], W[1], W[0]}

// For rounds [16 - 64)
#define ROUND_AND_SCHED_N_1_0(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 0 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	VPALIGNR $12, XDWORD0, XDWORD1, XTMP0;     \ // XTMP0 = W[-13] = {w6,w5,w4,w3}
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	VPSLLD   $7, XTMP0, XTMP1;                 \ // XTMP1 = W[-13] << 7 = {w6<<7,w5<<7,w4<<7,w3<<7}
	ADDL     (disp + 0*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	ADDL     (disp + 0*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	VPSRLD   $(32-7), XTMP0, XTMP0;            \ // XTMP0 = W[-13] >> 25 = {w6>>25,w5>>25,w4>>25,w3>>25}
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, y1;                            \
	ORL      b, y1;                            \
	VPOR     XTMP0, XTMP1, XTMP1;              \ // XTMP1 = W[-13] rol 7 = {ROTL(7,w6),ROTL(7,w5),ROTL(7,w4),ROTL(7,w3)}
	MOVL     a, h;                             \
	ANDL     b, h;                             \
	ANDL     c, y1;                            \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)  
	VPALIGNR $8, XDWORD2, XDWORD3, XTMP0;      \ // XTMP0 = W[-6] = {w13,w12,w11,w10}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     f, y1;                            \
	XORL     g, y1;                            \
	ANDL     e, y1;                            \
	VPXOR   XTMP1, XTMP0, XTMP0;               \ // XTMP0 = W[-6] ^ (W[-13] rol 7) 
	XORL     g, y1;                            \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG2(e, f, g) + h + SS1 + W = tt2  	 
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPALIGNR $12, XDWORD1, XDWORD2, XTMP1;     \ // XTMP1 = W[-9] = {w10,w9,w8,w7}
	P0(y2, y0, d);                             \
	VPXOR XDWORD0, XTMP1, XTMP1;               \ // XTMP1 = W[-9] ^ W[-16]

#define ROUND_AND_SCHED_N_1_1(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 1 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPSHUFD $0xA5, XDWORD3, XTMP2;             \ // XTMP2 = W[-3] {BBAA} {w14,w14,w13,w13}
	ROLL    $7, y2;                            \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 1*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPSRLQ  $17, XTMP2, XTMP2;                 \ // XTMP2 = W[-3] rol 15 {xBxA}
	ADDL     (disp + 1*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, y1;                            \
	ORL      b, y1;                            \
	VPXOR   XTMP1, XTMP2, XTMP2;               \ // XTMP2 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {xxxA}
	MOVL     a, h;                             \
	ANDL     b, h;                             \
	ANDL     c, y1;                            \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)     
	VPSHUFD $0x00, XTMP2, XTMP2;               \ // XTMP2 = {AAAA}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     f, y1;                            \
	XORL     g, y1;                            \
	ANDL     e, y1;                            \
	VPSRLQ  $17, XTMP2, XTMP3;                 \ // XTMP3 = XTMP2 rol 15 {xxxA}
	XORL     g, y1;                            \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG2(e, f, g) + h + SS1 + W = tt2  	
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPSRLQ  $9, XTMP2, XTMP4;                  \ // XTMP4 = XTMP2 rol 23 {xxxA}
	P0(y2, y0, d);                             \
	VPXOR    XTMP2, XTMP4, XTMP4;              \ // XTMP4 = XTMP2 XOR (XTMP2 rol 23 {xxxA})

#define ROUND_AND_SCHED_N_1_2(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 2 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPXOR    XTMP4, XTMP3, XTMP4;              \ // XTMP4 = XTMP2 ^ (XTMP2 rol 15 {xxxA}) ^ (XTMP2 rol 23 {xxxA})
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 2*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPXOR    XTMP4, XTMP0, XTMP2;              \ // XTMP2 = {..., ..., W[1], W[0]}
	ADDL     (disp + 2*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, y1;                            \
	ORL      b, y1;                            \
	VPALIGNR $4, XDWORD3, XTMP2, XTMP3;        \ // XTMP3 = {W[0], w15, w14, w13}
	MOVL     a, h;                             \
	ANDL     b, h;                             \
	ANDL     c, y1;                            \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)     
	VPSLLD   $15, XTMP3, XTMP4;                \
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     f, y1;                            \
	XORL     g, y1;                            \
	ANDL     e, y1;                            \
	VPSRLD   $(32-15), XTMP3, XTMP3;           \
	XORL     g, y1;                            \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG2(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPOR    XTMP3, XTMP4, XTMP4;               \ // XTMP4 = (W[-3] rol 15) {DCBA}
	P0(y2, y0, d);                             \
	VPXOR   XTMP1, XTMP4, XTMP4;               \ // XTMP4 = W[-9] ^ W[-16] ^ (W[-3] rol 15) {DCBA}

#define ROUND_AND_SCHED_N_1_3(disp, const, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3) \
	;                                          \ // #############################  RND N + 3 ############################//
	RORXL    $20, a, y0;                       \ // y0 = a <<< 12
	MOVL     e, y2;                            \
	ADDL     $const, y2;                       \
	ADDL     y0, y2;                           \ // y2 = a <<< 12 + e + T
	VPSLLD   $15, XTMP4, XTMP2;                \ 
	ROLL     $7, y2;                           \ // y2 = SS1
	XORL     y2, y0                            \ // y0 = SS2
	ADDL     (disp + 3*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                            \ // y2 = h + SS1 + W    
	VPSRLD   $(32-15), XTMP4, XTMP3;           \
	ADDL     (disp + 3*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                            \ // y0 = d + SS2 + W'
	MOVL     a, y1;                            \
	ORL      b, y1;                            \
	VPOR     XTMP3, XTMP2, XTMP3;              \ // XTMP3 = XTMP4 rol 15 {DCBA}
	MOVL     a, h;                             \
	ANDL     b, h;                             \
	ANDL     c, y1;                            \
	ORL      y1, h;                            \ // h =  (a AND b) OR (a AND c) OR (b AND c)
	VPSHUFB  R08_SHUFFLE_MASK, XTMP3, XTMP1;   \ // XTMP1 = XTMP4 rol 23 {DCBA}
	ADDL     y0, h;                            \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	MOVL     f, y1;                            \
	XORL     g, y1;                            \
	ANDL     e, y1;                            \
	VPXOR    XTMP3, XTMP4, XTMP3;              \ // XTMP3 = XTMP4 ^ (XTMP4 rol 15 {DCBA})
	XORL     g, y1;                            \ // y1 = GG2(e, f, g) = (e AND f) OR (NOT(e) AND g)
	ADDL     y1, y2;                           \ // y2 = GG2(e, f, g) + h + SS1 + W = tt2  
	ROLL     $9, b;                            \
	ROLL     $19, f;                           \
	VPXOR    XTMP3, XTMP1, XTMP1;              \ // XTMP1 = XTMP4 ^ (XTMP4 rol 15 {DCBA}) ^ (XTMP4 rol 23 {DCBA})
	P0(y2, y0, d);                             \
	VPXOR    XTMP1, XTMP0, XDWORD0;            \ // XWORD0 = {W[3], W[2], W[1], W[0]}

#define SS12(a, e, const, ss1, ss2) \
	RORXL    $20, a, ss2;                         \
	MOVL     e, ss1;                              \
	ADDL     $const, ss1;                         \
	ADDL     ss2, ss1;                            \ 
	ROLL     $7, ss1;                             \ // ss1 = (a <<< 12 + e + T) <<< 7
	XORL     ss1, ss2

// For rounds [0 - 16)
#define DO_ROUND_N_0(disp, idx, const, a, b, c, d, e, f, g, h) \
	;                                            \ // #############################  RND N + 0 ############################//
	SS12(a, e, const, y2, y0);                   \
	ADDL     (disp + idx*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                              \ // y2 = h + SS1 + W    
	ADDL     (disp + idx*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                              \ // y0 = d + SS2 + W'
	;                                            \
	MOVL     a, h;                               \
	XORL     b, h;                               \
	XORL     c, h;                               \
	ADDL     y0, h;                              \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                            \
	MOVL     e, y1;                              \
	XORL     f, y1;                              \
	XORL     g, y1;                              \
	ADDL     y1, y2;                             \ // y2 = GG(e, f, g) + h + SS1 + W = tt2  
	;                                            \
	ROLL     $9, b;                              \
	ROLL     $19, f;                             \
	;                                            \
	P0(y2, y0, d)

// For rounds [16 - 64)
#define DO_ROUND_N_1(disp, idx, const, a, b, c, d, e, f, g, h) \
	;                                            \ // #############################  RND N + 0 ############################//
	SS12(a, e, const, y2, y0);                   \
	ADDL     (disp + idx*4)(SP), y2;             \ // y2 = SS1 + W
	ADDL     h, y2;                              \ // y2 = h + SS1 + W    
	ADDL     (disp + idx*4 + 32)(SP), y0;        \ // y0 = SS2 + W'
	ADDL     d, y0;                              \ // y0 = d + SS2 + W'
	;                                            \
	MOVL     a, y1;                              \
	ORL      b, y1;                              \
	MOVL     a, h;                               \
	ANDL     b, h;                               \
	ANDL     c, y1;                              \
	ORL      y1, h;                              \ // h =  (a AND b) OR (a AND c) OR (b AND c)     
	ADDL     y0, h;                              \ // h = FF(a, b, c) + d + SS2 + W' = tt1
	;                                            \
	MOVL     f, y1;                              \
	XORL     g, y1;                              \
	ANDL     e, y1;                              \
	XORL     g, y1;                              \ // y1 = GG2(e, f, g)
	ADDL     y1, y2;                             \ // y2 = GG2(e, f, g) + h + SS1 + W = tt2  
	;                                            \
	ROLL     $9, b;                              \
	ROLL     $19, f;                             \
	;                                            \
	P0(y2, y0, d)

TEXT ·blockAVX2(SB), 0, $1040-32
	MOVQ dig+0(FP), CTX          // d.h[8]
	MOVQ p_base+8(FP), INP
	MOVQ p_len+16(FP), NUM_BYTES

	LEAQ -64(INP)(NUM_BYTES*1), NUM_BYTES // Pointer to the last block
	MOVQ NUM_BYTES, _INP_END(SP)

	VMOVDQU flip_mask<>(SB), BYTE_FLIP_MASK
	VMOVDQU r08_mask<>(SB), R08_SHUFFLE_MASK

	CMPQ NUM_BYTES, INP
	JE   avx2_only_one_block

	// Load initial digest
	MOVL 0(CTX), a  // a = H0
	MOVL 4(CTX), b  // b = H1
	MOVL 8(CTX), c  // c = H2
	MOVL 12(CTX), d // d = H3
	MOVL 16(CTX), e // e = H4
	MOVL 20(CTX), f // f = H5
	MOVL 24(CTX), g // g = H6
	MOVL 28(CTX), h // h = H7

avx2_loop: // at each iteration works with one block (512 bit)

	VMOVDQU (0*32)(INP), XTMP0
	VMOVDQU (1*32)(INP), XTMP1
	VMOVDQU (2*32)(INP), XTMP2
	VMOVDQU (3*32)(INP), XTMP3

	// Apply Byte Flip Mask: LE -> BE
	VPSHUFB BYTE_FLIP_MASK, XTMP0, XTMP0
	VPSHUFB BYTE_FLIP_MASK, XTMP1, XTMP1
	VPSHUFB BYTE_FLIP_MASK, XTMP2, XTMP2
	VPSHUFB BYTE_FLIP_MASK, XTMP3, XTMP3

	// Transpose data into high/low parts
	VPERM2I128 $0x20, XTMP2, XTMP0, XDWORD0 // w19, w18, w17, w16;  w3,  w2,  w1,  w0
	VPERM2I128 $0x31, XTMP2, XTMP0, XDWORD1 // w23, w22, w21, w20;  w7,  w6,  w5,  w4
	VPERM2I128 $0x20, XTMP3, XTMP1, XDWORD2 // w27, w26, w25, w24; w11, w10,  w9,  w8
	VPERM2I128 $0x31, XTMP3, XTMP1, XDWORD3 // w31, w30, w29, w28; w15, w14, w13, w12

avx2_last_block_enter:
	ADDQ $64, INP

avx2_schedule_compress: // for w0 - w47
	// Do 4 rounds and scheduling
	VMOVDQU XDWORD0, (_XFER + 0*32)(SP)
	VPXOR  XDWORD0, XDWORD1, XFER
	VMOVDQU XFER, (_XFER + 1*32)(SP)
	ROUND_AND_SCHED_N_0_0(_XFER + 0*32, T0, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_0_1(_XFER + 0*32, T1, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_0_2(_XFER + 0*32, T2, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_0_3(_XFER + 0*32, T3, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD1, (_XFER + 2*32)(SP)
	VPXOR  XDWORD1, XDWORD2, XFER
	VMOVDQU XFER, (_XFER + 3*32)(SP)
	ROUND_AND_SCHED_N_0_0(_XFER + 2*32, T4, e, f, g, h, a, b, c, d, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_0_1(_XFER + 2*32, T5, d, e, f, g, h, a, b, c, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_0_2(_XFER + 2*32, T6, c, d, e, f, g, h, a, b, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_0_3(_XFER + 2*32, T7, b, c, d, e, f, g, h, a, XDWORD1, XDWORD2, XDWORD3, XDWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD2, (_XFER + 4*32)(SP)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 5*32)(SP)
	ROUND_AND_SCHED_N_0_0(_XFER + 4*32, T8, a, b, c, d, e, f, g, h, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_0_1(_XFER + 4*32, T9, h, a, b, c, d, e, f, g, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_0_2(_XFER + 4*32, T10, g, h, a, b, c, d, e, f, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_0_3(_XFER + 4*32, T11, f, g, h, a, b, c, d, e, XDWORD2, XDWORD3, XDWORD0, XDWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD3, (_XFER + 6*32)(SP)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 7*32)(SP)
	ROUND_AND_SCHED_N_0_0(_XFER + 6*32, T12, e, f, g, h, a, b, c, d, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_0_1(_XFER + 6*32, T13, d, e, f, g, h, a, b, c, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_0_2(_XFER + 6*32, T14, c, d, e, f, g, h, a, b, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_0_3(_XFER + 6*32, T15, b, c, d, e, f, g, h, a, XDWORD3, XDWORD0, XDWORD1, XDWORD2)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD0, (_XFER + 8*32)(SP)
	VPXOR  XDWORD0, XDWORD1, XFER
	VMOVDQU XFER, (_XFER + 9*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 8*32, T16, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER + 8*32, T17, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER + 8*32, T18, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER + 8*32, T19, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD1, (_XFER + 10*32)(SP)
	VPXOR  XDWORD1, XDWORD2, XFER
	VMOVDQU XFER, (_XFER + 11*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 10*32, T20, e, f, g, h, a, b, c, d, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_1(_XFER + 10*32, T21, d, e, f, g, h, a, b, c, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_2(_XFER + 10*32, T22, c, d, e, f, g, h, a, b, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_3(_XFER + 10*32, T23, b, c, d, e, f, g, h, a, XDWORD1, XDWORD2, XDWORD3, XDWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD2, (_XFER + 12*32)(SP)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 13*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 12*32, T24, a, b, c, d, e, f, g, h, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_1(_XFER + 12*32, T25, h, a, b, c, d, e, f, g, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_2(_XFER + 12*32, T26, g, h, a, b, c, d, e, f, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_3(_XFER + 12*32, T27, f, g, h, a, b, c, d, e, XDWORD2, XDWORD3, XDWORD0, XDWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD3, (_XFER + 14*32)(SP)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 15*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 14*32, T28, e, f, g, h, a, b, c, d, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_1(_XFER + 14*32, T29, d, e, f, g, h, a, b, c, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_2(_XFER + 14*32, T30, c, d, e, f, g, h, a, b, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_3(_XFER + 14*32, T31, b, c, d, e, f, g, h, a, XDWORD3, XDWORD0, XDWORD1, XDWORD2)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD0, (_XFER + 16*32)(SP)
	VPXOR  XDWORD0, XDWORD1, XFER
	VMOVDQU XFER, (_XFER + 17*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 16*32, T32, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER + 16*32, T33, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER + 16*32, T34, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER + 16*32, T35, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD1, (_XFER + 18*32)(SP)
	VPXOR  XDWORD1, XDWORD2, XFER
	VMOVDQU XFER, (_XFER + 19*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 18*32, T36, e, f, g, h, a, b, c, d, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_1(_XFER + 18*32, T37, d, e, f, g, h, a, b, c, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_2(_XFER + 18*32, T38, c, d, e, f, g, h, a, b, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	ROUND_AND_SCHED_N_1_3(_XFER + 18*32, T39, b, c, d, e, f, g, h, a, XDWORD1, XDWORD2, XDWORD3, XDWORD0)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD2, (_XFER + 20*32)(SP)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 21*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 20*32, T40, a, b, c, d, e, f, g, h, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_1(_XFER + 20*32, T41, h, a, b, c, d, e, f, g, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_2(_XFER + 20*32, T42, g, h, a, b, c, d, e, f, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	ROUND_AND_SCHED_N_1_3(_XFER + 20*32, T43, f, g, h, a, b, c, d, e, XDWORD2, XDWORD3, XDWORD0, XDWORD1)

	// Do 4 rounds and scheduling
	VMOVDQU XDWORD3, (_XFER + 22*32)(SP)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 23*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 22*32, T44, e, f, g, h, a, b, c, d, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_1(_XFER + 22*32, T45, d, e, f, g, h, a, b, c, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_2(_XFER + 22*32, T46, c, d, e, f, g, h, a, b, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	ROUND_AND_SCHED_N_1_3(_XFER + 22*32, T47, b, c, d, e, f, g, h, a, XDWORD3, XDWORD0, XDWORD1, XDWORD2)

	// w48 - w63 processed with only 4 rounds scheduling (last 16 rounds)
	// Do 4 rounds and scheduling
	VMOVDQU XDWORD0, (_XFER + 24*32)(SP)
	VPXOR  XDWORD0, XDWORD1, XFER
	VMOVDQU XFER, (_XFER + 25*32)(SP)
	ROUND_AND_SCHED_N_1_0(_XFER + 24*32, T48, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_1(_XFER + 24*32, T49, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_2(_XFER + 24*32, T50, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	ROUND_AND_SCHED_N_1_3(_XFER + 24*32, T51, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)  

	// w52 - w63 processed with no scheduling (last 12 rounds)
	// Do 4 rounds
	VMOVDQU XDWORD1, (_XFER + 26*32)(SP)
	VPXOR  XDWORD1, XDWORD2, XFER
	VMOVDQU XFER, (_XFER + 27*32)(SP)
	DO_ROUND_N_1(_XFER + 26*32, 0, T52, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 26*32, 1, T53, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 26*32, 2, T54, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 26*32, 3, T55, b, c, d, e, f, g, h, a)

	// Do 4 rounds
	VMOVDQU XDWORD2, (_XFER + 28*32)(SP)
	VPXOR  XDWORD2, XDWORD3, XFER
	VMOVDQU XFER, (_XFER + 29*32)(SP)
	DO_ROUND_N_1(_XFER + 28*32, 0, T56, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 28*32, 1, T57, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 28*32, 2, T58, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 28*32, 3, T59, f, g, h, a, b, c, d, e)

	// Do 4 rounds
	VMOVDQU XDWORD3, (_XFER + 30*32)(SP)
	VPXOR  XDWORD3, XDWORD0, XFER
	VMOVDQU XFER, (_XFER + 31*32)(SP)
	DO_ROUND_N_1(_XFER + 30*32, 0, T60, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 30*32, 1, T61, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 30*32, 2, T62, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 30*32, 3, T63, b, c, d, e, f, g, h, a)

	xorm(  0(CTX), a)
	xorm(  4(CTX), b)
	xorm(  8(CTX), c)
	xorm( 12(CTX), d)
	xorm( 16(CTX), e)
	xorm( 20(CTX), f)
	xorm( 24(CTX), g)
	xorm( 28(CTX), h)

	CMPQ _INP_END(SP), INP
	JB   done_hash

avx2_compress: // Do second block using previously scheduled results
	DO_ROUND_N_0(_XFER + 0*32 + 16, 0, T0, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(_XFER + 0*32 + 16, 1, T1, h, a, b, c, d, e, f, g)
	DO_ROUND_N_0(_XFER + 0*32 + 16, 2, T2, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(_XFER + 0*32 + 16, 3, T3, f, g, h, a, b, c, d, e)

	DO_ROUND_N_0(_XFER + 2*32 + 16, 0, T4, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(_XFER + 2*32 + 16, 1, T5, d, e, f, g, h, a, b, c)
	DO_ROUND_N_0(_XFER + 2*32 + 16, 2, T6, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(_XFER + 2*32 + 16, 3, T7, b, c, d, e, f, g, h, a)

	DO_ROUND_N_0(_XFER + 4*32 + 16, 0, T8, a, b, c, d, e, f, g, h)
	DO_ROUND_N_0(_XFER + 4*32 + 16, 1, T9, h, a, b, c, d, e, f, g)
	DO_ROUND_N_0(_XFER + 4*32 + 16, 2, T10, g, h, a, b, c, d, e, f)
	DO_ROUND_N_0(_XFER + 4*32 + 16, 3, T11, f, g, h, a, b, c, d, e)

	DO_ROUND_N_0(_XFER + 6*32 + 16, 0, T12, e, f, g, h, a, b, c, d)
	DO_ROUND_N_0(_XFER + 6*32 + 16, 1, T13, d, e, f, g, h, a, b, c)
	DO_ROUND_N_0(_XFER + 6*32 + 16, 2, T14, c, d, e, f, g, h, a, b)
	DO_ROUND_N_0(_XFER + 6*32 + 16, 3, T15, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 8*32 + 16, 0, T16, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 8*32 + 16, 1, T17, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 8*32 + 16, 2, T18, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 8*32 + 16, 3, T19, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 10*32 + 16, 0, T20, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 10*32 + 16, 1, T21, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 10*32 + 16, 2, T22, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 10*32 + 16, 3, T23, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 12*32 + 16, 0, T24, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 12*32 + 16, 1, T25, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 12*32 + 16, 2, T26, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 12*32 + 16, 3, T27, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 14*32 + 16, 0, T28, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 14*32 + 16, 1, T29, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 14*32 + 16, 2, T30, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 14*32 + 16, 3, T31, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 16*32 + 16, 0, T32, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 16*32 + 16, 1, T33, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 16*32 + 16, 2, T34, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 16*32 + 16, 3, T35, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 18*32 + 16, 0, T36, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 18*32 + 16, 1, T37, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 18*32 + 16, 2, T38, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 18*32 + 16, 3, T39, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 20*32 + 16, 0, T40, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 20*32 + 16, 1, T41, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 20*32 + 16, 2, T42, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 20*32 + 16, 3, T43, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 22*32 + 16, 0, T44, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 22*32 + 16, 1, T45, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 22*32 + 16, 2, T46, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 22*32 + 16, 3, T47, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 24*32 + 16, 0, T48, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 24*32 + 16, 1, T49, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 24*32 + 16, 2, T50, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 24*32 + 16, 3, T51, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 26*32 + 16, 0, T52, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 26*32 + 16, 1, T53, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 26*32 + 16, 2, T54, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 26*32 + 16, 3, T55, b, c, d, e, f, g, h, a)

	DO_ROUND_N_1(_XFER + 28*32 + 16, 0, T56, a, b, c, d, e, f, g, h)
	DO_ROUND_N_1(_XFER + 28*32 + 16, 1, T57, h, a, b, c, d, e, f, g)
	DO_ROUND_N_1(_XFER + 28*32 + 16, 2, T58, g, h, a, b, c, d, e, f)
	DO_ROUND_N_1(_XFER + 28*32 + 16, 3, T59, f, g, h, a, b, c, d, e)

	DO_ROUND_N_1(_XFER + 30*32 + 16, 0, T60, e, f, g, h, a, b, c, d)
	DO_ROUND_N_1(_XFER + 30*32 + 16, 1, T61, d, e, f, g, h, a, b, c)
	DO_ROUND_N_1(_XFER + 30*32 + 16, 2, T62, c, d, e, f, g, h, a, b)
	DO_ROUND_N_1(_XFER + 30*32 + 16, 3, T63, b, c, d, e, f, g, h, a)

	ADDQ $64, INP

	xorm(  0(CTX), a)
	xorm(  4(CTX), b)
	xorm(  8(CTX), c)
	xorm( 12(CTX), d)
	xorm( 16(CTX), e)
	xorm( 20(CTX), f)
	xorm( 24(CTX), g)
	xorm( 28(CTX), h)

	CMPQ _INP_END(SP), INP
	JA   avx2_loop
	JB   done_hash

avx2_do_last_block:

	VMOVDQU 0(INP), XWORD0
	VMOVDQU 16(INP), XWORD1
	VMOVDQU 32(INP), XWORD2
	VMOVDQU 48(INP), XWORD3

	VPSHUFB X_BYTE_FLIP_MASK, XWORD0, XWORD0
	VPSHUFB X_BYTE_FLIP_MASK, XWORD1, XWORD1
	VPSHUFB X_BYTE_FLIP_MASK, XWORD2, XWORD2
	VPSHUFB X_BYTE_FLIP_MASK, XWORD3, XWORD3

	JMP avx2_last_block_enter

avx2_only_one_block:
	// Load initial digest
	MOVL 0(CTX), a  // a = H0
	MOVL 4(CTX), b  // b = H1
	MOVL 8(CTX), c  // c = H2
	MOVL 12(CTX), d // d = H3
	MOVL 16(CTX), e // e = H4
	MOVL 20(CTX), f // f = H5
	MOVL 24(CTX), g // g = H6
	MOVL 28(CTX), h // h = H7

	JMP avx2_do_last_block

done_hash:
	VZEROUPPER
	RET

// shuffle byte order from LE to BE
DATA flip_mask<>+0x00(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x08(SB)/8, $0x0c0d0e0f08090a0b
DATA flip_mask<>+0x10(SB)/8, $0x0405060700010203
DATA flip_mask<>+0x18(SB)/8, $0x0c0d0e0f08090a0b
GLOBL flip_mask<>(SB), 8, $32

DATA r08_mask<>+0x00(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x08(SB)/8, $0x0E0D0C0F0A09080B
DATA r08_mask<>+0x10(SB)/8, $0x0605040702010003
DATA r08_mask<>+0x18(SB)/8, $0x0E0D0C0F0A09080B
GLOBL r08_mask<>(SB), 8, $32
