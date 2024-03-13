package ascon

func additionalData128a(s *state, ad []byte) {
    additionalData128aGeneric(s, ad)
}

func encryptBlocks128a(s *state, dst, src []byte) {
    encryptBlocks128aGeneric(s, dst, src)
}

func decryptBlocks128a(s *state, dst, src []byte) {
    decryptBlocks128aGeneric(s, dst, src)
}

func round(s *state, C uint64) {
    roundGeneric(s, C)
}

func p12(s *state) {
    p12Generic(s)
}

func p8(s *state) {
    p8Generic(s)
}

func p6(s *state) {
    p6Generic(s)
}
