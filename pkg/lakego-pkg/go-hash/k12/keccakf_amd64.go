//go:build amd64 && !purego && gc

package k12

// This function is implemented in keccakf_amd64.s.

//go:noescape

func keccakF1600(a *[25]uint64, nr int)
