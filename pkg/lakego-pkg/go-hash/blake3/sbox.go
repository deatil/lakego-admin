package blake3

const BLAKE3_KEY_LEN   = 32
const BLAKE3_OUT_LEN   = 32
const BLAKE3_BLOCK_LEN = 64
const BLAKE3_CHUNK_LEN = 1024
const BLAKE3_MAX_DEPTH = 54

const (
    CHUNK_START         = 1 << 0
    CHUNK_END           = 1 << 1
    PARENT              = 1 << 2
    ROOT                = 1 << 3
    KEYED_HASH          = 1 << 4
    DERIVE_KEY_CONTEXT  = 1 << 5
    DERIVE_KEY_MATERIAL = 1 << 6
)

var iv = [8]uint32{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372,
    0xA54FF53A, 0x510E527F, 0x9B05688C,
    0x1F83D9AB, 0x5BE0CD19,
}

var MSG_SCHEDULE = [7][16]uint32{
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
}
