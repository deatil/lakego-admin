package sm9curve

import (
    "math/big"
)

func bigFromBase10(s string) *big.Int {
    n, _ := new(big.Int).SetString(s, 10)
    return n
}

// u is the BN parameter that determines the prime: 600000000058f98a.
var u, _ = new(big.Int).SetString("600000000058f98a", 16)

// p is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
var p, _ = new(big.Int).SetString("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d", 16)

// Order is the number of elements in both G₁ and G₂: 36u⁴+36u³+18u²+6u+1.
var Order, _ = new(big.Int).SetString("b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25", 16)

//gx,gy are coordinates of G1 in montEncode form
//var gx = gfP{0x22e935e29860501b,0xa946fd5e0073282c,0xefd0cec817a649be,0x5129787c869140b5}
//var gy = gfP{0xee779649eb87f7c7,0x15563cbdec30a576,0x326353912824efbf,0x7215717763c39828}

// p2 is p, represented as little-endian 64-bit words.
var p2 = [4]uint64{0xe56f9b27e351457d, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1}

// np is the negative inverse of p, mod 2^256.
var np = [4]uint64{0x892bc42c2f2ee42b, 0x181ae39613c8dbaf, 0x966a4b291522b137, 0xafd2bac5558a13b3}

// rN1 is R^-1 where R = 2^256 mod p.
var rN1 = &gfP{0x0a1c7970e5df544d, 0xe74504e9a96b56cc, 0xcda02d92d4d62924, 0x7d2bc576fdf597d1}

// r2 is R^2 where R = 2^256 mod p.
var r2 = &gfP{0x27dea312b417e2d2, 0x88f8105fae1a5d3f, 0xe479b522d6706e7b, 0x2ea795a656f62fbd}

// r3 is R^3 where R = 2^256 mod p.
var r3 = &gfP{0x130257769df5827e, 0x36920fc0837ec76e, 0xcbec24519c22a142, 0x219be84a7c687090}

// pPlus1Over4 is (p+1)/4.
var pPlus1Over4 = [4]uint64{0xf95be6c9f8d4515f, 0x487ca4d2c69ebbb6, 0x7580ead3fd63b1d1, 0x2d90000000a8e9bc}

//pPlus3Over4 is (p+3)/4
var pPlus3Over4 = [4]uint64{0xf95be6c9f8d45160, 0x487ca4d2c69ebbb6, 0x7580ead3fd63b1d1, 0x2d90000000a8e9bc}

//twoTo2kPlus1 is 2^(2k+1),where k = (p-1)/4
var twoTo2kPlus1 = gfP{0xe56f9b27e351457c, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1}

//pMinus1 is p-1
var pMinus1 = gfP{0xcadf364fc6a28afa, 0x43e5269634f5ddb7, 0xac07569feb1d8e8a, 0x6c80000005474de3}

// pMinus2 is p-2.
var pMinus2 = [4]uint64{0xe56f9b27e351457b, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1}

// pMinus1Over2 is (p-1)/2.
var pMinus1Over2 = [4]uint64{0xf2b7cd93f1a8a2be, 0x90f949a58d3d776d, 0xeb01d5a7fac763a2, 0x5b2000000151d378}

// pMinus1Over2 is (p-1)/4.
var pMinus1Over4 = [4]uint64{0xf95be6c9f8d4515f, 0x487ca4d2c69ebbb6, 0x7580ead3fd63b1d1, 0x2d90000000a8e9bc}

//ξ=bi, b = (-1/2) mod p (in montEncode form).
//var b = gfP{0xf2b7cd93f1a8a2be,0x90f949a58d3d776d,0xeb01d5a7fac763a2,0x5b2000000151d378}
var bi = gfP{0xe56f9b27e351457d, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0x3640000002a3a6f1}

// s is the Montgomery encoding of the square root of -3. Then, s = sqrt(-3) * 2^256 mod p.
var s = &gfP{0x7b2e07c770965b71, 0xa9bce0778466aa4b, 0x2e12588fcbc9e459, 0x8f4000000d3242b9}

// sMinus1Over2 is the Montgomery encoding of (s-1)/2. Then, sMinus1Over2 = ( (s-1) / 2) * 2^256 mod p.
var sMinus1Over2 = &gfP{0xb04ed177a9f3d077, 0x65d7b9e14f70cc93, 0x820b01efe0ac55cf, 0x22c0000007eaf4d5}

// xiToPMinus1Over2 is ξ^((p-1)/2) where ξ = (-1/2)i.
var xiToPMinus1Over2 = &gfP{0xabbaac18a46a2054, 0x46ee57561222c759, 0x1dae609fa0e23561, 0x1df7113dae0adc3c}

// xiToPMinus1Over3 is ξ^((p-1)/3) where ξ = (-1/2)i.
var xiToPMinus1Over3 = &gfP{0x646a4b5a4e6783b9, 0xd5e4017f8d980f9d, 0x8d8bf6fd0cdfe790, 0x2d4ac18b775a8f7b}

// xiTo2PMinus2Over3 is ξ^((2p-2)/3) where ξ = (-1/2)i.
var xiTo2PMinus2Over3 = &gfP{0x2f4981aa150a0eb3, 0x19c92815c28ded55, 0x39934d9cf7fd761b, 0x99cac18b7ca1dd5f}

// xiToPMinus1Over6 is ξ^((p-1)/6) where ξ = (-1/2)i.
var xiToPMinus1Over6 = &gfP{0xe0e3f0ae068e0476, 0xc3c418861c042d7a, 0x3cca13fbbf32f288, 0x6ae5153810898de}

// xiToPSquaredMinus1Over3 is ξ^((p²-1)/3) where ξ = (-1/2)i.
var xiToPSquaredMinus1Over3 = &gfP{0x2f4981aa150a0eb3, 0x19c92815c28ded55, 0x39934d9cf7fd761b, 0x99cac18b7ca1dd5f}

// xiTo2PSquaredMinus2Over3 is ξ^((2p²-2)/3) where ξ = (-1/2)i.
var xiTo2PSquaredMinus2Over3 = &gfP{0x81054fcd94e9c1c4, 0x4c0e91cb8ce2df3e, 0x4877b452e8aedfb4, 0x88f53e748b491776}

// xiToPSquaredMinus1Over6 is ξ^((1p²-1)/6) where ξ = (-1/2)i.
var xiToPSquaredMinus1Over6 = &gfP{0x646a4b5a4e6783b9, 0xd5e4017f8d980f9d, 0x8d8bf6fd0cdfe790, 0x2d4ac18b775a8f7b}
