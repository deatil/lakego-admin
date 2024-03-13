package spritz

func Hash(m []byte, r byte) []byte {
    var c spritzCipher

    c.initializeState()

    c.absorb(m)
    c.absorbStop()

    // hash length
    c.absorbByte(r)

    return c.squeeze(int(r))
}
