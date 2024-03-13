package grain

func next(s *state) uint32 {
    return nextGeneric(s)
}

func accumulate(reg, acc uint64, ms, pt uint16) (uint64, uint64) {
    return accumulateGeneric(reg, acc, ms, pt)
}
