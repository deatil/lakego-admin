//go:build !purego

package sm3

import "golang.org/x/sys/cpu"

// 汇编部分来自于 github.com/emmansun/gmsm/sm3

var useAVX2 = cpu.X86.HasAVX2 && cpu.X86.HasBMI2
var useAVX = cpu.X86.HasAVX
var useSSSE3 = cpu.X86.HasSSSE3

//go:noescape
func blockAMD64(dig *digest, p []byte)

//go:noescape
func blockSIMD(dig *digest, p []byte)

//go:noescape
func blockAVX2(dig *digest, p []byte)

func block(dig *digest, p []byte) {
	if useAVX2 {
		blockAVX2(dig, p)
	} else if useSSSE3 || useAVX {
		blockSIMD(dig, p)
	} else {
		blockAMD64(dig, p)
	}
}
