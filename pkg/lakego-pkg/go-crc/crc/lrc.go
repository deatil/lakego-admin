package crc

// LRC 算法
func LRC(data []byte) uint8 {
    var lrc = byte(0)

    for _, d := range data {
        lrc += byte(d)
    }

    return uint8(-int8(lrc))
}
