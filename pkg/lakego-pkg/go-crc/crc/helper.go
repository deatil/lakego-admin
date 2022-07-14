package crc

import (
    "fmt"
)

// 输出 16 进制字符
func ToHexString(data uint8, typ ...string) string {
    if len(typ) > 0 {
        switch typ[0] {
            case "crc3", "crc4":
                return fmt.Sprintf("%01X", data)
            case "crc5", "crc6", "crc7", "lrc", "bcc":
                return fmt.Sprintf("%02X", data)
        }
    }

    return fmt.Sprintf("%X", data)
}

// 输出二进制字符
func ToBinString(data uint8, typ ...string) string {
    if len(typ) > 0 {
        switch typ[0] {
            case "crc3", "crc4":
                return fmt.Sprintf("%04b", data)
            case "crc5":
                return fmt.Sprintf("%05b", data)
            case "crc6":
                return fmt.Sprintf("%06b", data)
            case "crc7":
                return fmt.Sprintf("%07b", data)
            case "lrc", "bcc":
                return fmt.Sprintf("%08b", data)
        }
    }

    return fmt.Sprintf("%b", data)
}

