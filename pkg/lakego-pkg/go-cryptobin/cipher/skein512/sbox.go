package skein512

const streamOutLen = (1<<64 - 1) / 8 // 2^64 - 1 bits

// Argument types (in the order they must be used).
const (
    keyArg     uint64 = 0
    configArg  uint64 = 4
    keyIDArg   uint64 = 16
    nonceArg   uint64 = 20
    messageArg uint64 = 48
    outputArg  uint64 = 63
)

const (
    firstBlockFlag uint64 = 1 << 62
    lastBlockFlag  uint64 = 1 << 63
)

var schemaId = []byte{'S', 'H', 'A', '3', 1, 0, 0, 0}
var outTweak = [2]uint64{8, outputArg<<56 | firstBlockFlag | lastBlockFlag}
