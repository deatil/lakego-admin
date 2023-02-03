package bencode

import (
    "fmt"
    "unsafe"
    "reflect"
)

// Wow Go is retarded.
var (
    marshalerType   = reflect.TypeOf((*Marshaler)(nil)).Elem()
    unmarshalerType = reflect.TypeOf((*Unmarshaler)(nil)).Elem()
)

func bytesAsString(b []byte) string {
    return *(*string)(unsafe.Pointer(&b))
}

// splitPieceHashes 切割Pieces
func splitPieceHashes(pieces string) ([][20]byte, error) {
    // SHA-1 hash的长度
    hashLen := 20
    buf := []byte(pieces)

    if len(buf)%hashLen != 0 {
        // 片段的长度不正确
        err := fmt.Errorf("Received malformed pieces of length %d", len(buf))
        return nil, err
    }

    // hash 的总数
    numHashes := len(buf) / hashLen
    hashes := make([][20]byte, numHashes)

    for i := 0; i < numHashes; i++ {
        copy(hashes[i][:], buf[i*hashLen:(i+1)*hashLen])
    }
    
    return hashes, nil
}
