//go:build !boringcrypto

package x509

func boringAllowCert(c *Certificate) bool { return true }
