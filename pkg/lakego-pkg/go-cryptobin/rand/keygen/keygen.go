package keygen

import (
    "io"
)

type Keygen struct {
    length int
    reader io.Reader
}

func New(length int, reader io.Reader) *Keygen {
    return &Keygen{
        length: length,
        reader: reader,
    }
}

func (this *Keygen) GenerateKey() ([]byte, error) {
    num := this.length / 8

    key := make([]byte, num)

    _, err := this.reader.Read(key)
    if err != nil {
        return nil, err
    }

    genKey := make([]byte, num)
    copy(genKey, key)

    for i := num; i < len(key); {
        for j := 0; j < num && i < len(key); j, i = j+1, i+1 {
            genKey[j] ^= key[i]
        }
    }

    return genKey, nil
}
