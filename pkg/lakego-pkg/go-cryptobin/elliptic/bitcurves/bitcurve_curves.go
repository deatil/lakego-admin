// Package bitelliptic implements several Koblitz elliptic curves over prime fields.
package bitcurves

import (
    "sync"
    "math/big"
)

// curve parameters taken from:
// http://www.secg.org/collateral/sec2_final.pdf

var (
    initonce sync.Once
    secp160k1, secp192k1, secp224k1, secp256k1 *BitCurve
)

func initAll() {
    initS160()
    initS192()
    initS224()
    initS256()
}

func initS160() {
    // See SEC 2 section 2.4.1
    secp160k1 = new(BitCurve)
    secp160k1.Name = "secp160k1"
    secp160k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16)
    secp160k1.N, _ = new(big.Int).SetString("0100000000000000000001B8FA16DFAB9ACA16B6B3", 16)
    secp160k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000007", 16)
    secp160k1.Gx, _ = new(big.Int).SetString("3B4C382CE37AA192A4019E763036F4F5DD4D7EBB", 16)
    secp160k1.Gy, _ = new(big.Int).SetString("938CF935318FDCED6BC28286531733C3F03C4FEE", 16)
    secp160k1.BitSize = 160
}

func initS192() {
    // See SEC 2 section 2.5.1
    secp192k1 = new(BitCurve)
    secp192k1.Name = "secp192k1"
    secp192k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", 16)
    secp192k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", 16)
    secp192k1.B, _ = new(big.Int).SetString("000000000000000000000000000000000000000000000003", 16)
    secp192k1.Gx, _ = new(big.Int).SetString("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", 16)
    secp192k1.Gy, _ = new(big.Int).SetString("9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", 16)
    secp192k1.BitSize = 192
}

func initS224() {
    // See SEC 2 section 2.6.1
    secp224k1 = new(BitCurve)
    secp224k1.Name = "secp224k1"
    secp224k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D", 16)
    secp224k1.N, _ = new(big.Int).SetString("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7", 16)
    secp224k1.B, _ = new(big.Int).SetString("00000000000000000000000000000000000000000000000000000005", 16)
    secp224k1.Gx, _ = new(big.Int).SetString("A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C", 16)
    secp224k1.Gy, _ = new(big.Int).SetString("7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5", 16)
    secp224k1.BitSize = 224
}

func initS256() {
    // See SEC 2 section 2.7.1
    secp256k1 = new(BitCurve)
    secp256k1.Name = "secp256k1"
    secp256k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    secp256k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    secp256k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
    secp256k1.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    secp256k1.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    secp256k1.BitSize = 256
}
