package haraka

var hasAES = false

// Haraka256 calculates the Harakaa v2 hash of a 256-bit
// input and places the 256-bit result in output.
func Haraka256(input [32]byte) (output [32]byte) {
    if hasAES {
        haraka256AES(&rc[0], &output[0], &input[0])
    } else {
        haraka256Ref(&output, &input)
    }

    return
}

// Haraka512 calculates the Harakaa v2 hash of a 512-bit
// input and places the 256-bit result in output.
func Haraka512(input [64]byte) (output [32]byte) {
    if hasAES {
        haraka512AES(&rc[0], &output[0], &input[0])
    } else {
        haraka512Ref(&output, &input)
    }

    return
}

func haraka256AES(rc *uint32, dst, src *byte)
func haraka512AES(rc *uint32, dst, src *byte)
