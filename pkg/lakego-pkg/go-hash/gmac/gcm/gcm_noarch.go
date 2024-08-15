//go:build !((amd64 || arm64) && !purego && (!gccgo || go1.18))
// +build !amd64,!arm64 purego gccgo,!go1.18

package gcm

func init() {
    gcmInit = gcmInitGo
    gcmDeriveCounter = gcmDeriveCounterGo
    gcmUpdate = gcmUpdateGo
    gcmAuth = gcmAuthGo
    gcmFinish = gcmFinishGo
}
