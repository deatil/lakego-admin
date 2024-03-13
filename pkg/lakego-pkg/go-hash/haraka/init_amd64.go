// +build amd64

package haraka

import "golang.org/x/sys/cpu"

func init() {
    hasAES = cpu.X86.HasAES
}
