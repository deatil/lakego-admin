package crypto

import (
    "fmt"
    "crypto/rc4"

    "golang.org/x/crypto/xts"
    "golang.org/x/crypto/chacha20"
    "golang.org/x/crypto/chacha20poly1305"
    
    "github.com/deatil/go-cryptobin/tool"
)

// 加密
func (this Cryptobin) GuessEncrypt() Cryptobin {
    switch this.multiple {
        // 32 bytes key and a 12 or 24 bytes nonce
        case "Chacha20":
            nonce, ok := this.config["nonce"]
            if !ok {
                this.Error = fmt.Errorf("chacha20 error: nonce is empty.")
                return this
            }

            chacha, err := chacha20.NewUnauthenticatedCipher(this.key, nonce.([]byte))
            if err != nil {
                this.Error = fmt.Errorf("chacha20.New(),error:%w", err)
                return this
            }

            counter, ok := this.config["counter"]
            if ok {
                chacha.SetCounter(counter.(uint32))
            }

            dst := make([]byte, len(this.data))

            chacha.XORKeyStream(dst, this.data)

            this.parsedData = dst

            return this
        // 32 bytes
        case "Chacha20poly1305":
            chacha, err := chacha20poly1305.New(this.key)
            if err != nil {
                this.Error = fmt.Errorf("chacha20poly1305.New(),error:%w", err)
                return this
            }

            nonce, ok := this.config["nonce"]
            if !ok {
                this.Error = fmt.Errorf("chacha20poly1305 error: nonce is empty.")
                return this
            }

            additional, _ := this.config["additional"]

            this.parsedData = chacha.Seal(nil, nonce.([]byte), this.data, additional.([]byte))

            return this
        // RC4 key, at least 1 byte and at most 256 bytes.
        case "RC4":
            rc, err := rc4.NewCipher(this.key)
            if err != nil {
                this.Error = fmt.Errorf("rc4.NewCipher(),error:%w", err)
                return this
            }

            dst := make([]byte, len(this.data))

            rc.XORKeyStream(dst, this.data)

            this.parsedData = dst

            return this
        // Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
        case "Xts":
            cipher, ok := this.config["cipher"]
            if !ok {
                this.Error = fmt.Errorf("Xts error: cipher is empty.")
                return this
            }

            sectorNum, ok := this.config["sector_num"]
            if !ok {
                this.Error = fmt.Errorf("Xts error: sector_num is empty.")
                return this
            }

            cipherFunc := tool.NewCipher().GetFunc(cipher.(string))

            xc, err := xts.NewCipher(cipherFunc, this.key)
            if err != nil {
                this.Error = fmt.Errorf("xts.NewCipher(),error:%w", err)
                return this
            }

            // 大小
            bs := 16

            plainPadding := this.Padding(this.data, bs)

            dst := make([]byte, len(plainPadding))

            xc.Encrypt(dst, plainPadding, sectorNum.(uint64))

            this.parsedData = dst

            return this
        default:
            this.Error = fmt.Errorf("Multiple [%s] is error.", this.multiple)

            return this
    }
}

// 解密
func (this Cryptobin) GuessDecrypt() Cryptobin {
    switch this.multiple {
        // 32 bytes key and a 12 or 24 bytes nonce
        case "Chacha20":
            nonce, ok := this.config["nonce"]
            if !ok {
                this.Error = fmt.Errorf("chacha20 error: nonce is empty.")
                return this
            }

            chacha, err := chacha20.NewUnauthenticatedCipher(this.key, nonce.([]byte))
            if err != nil {
                this.Error = fmt.Errorf("chacha20.New(),error:%w", err)
                return this
            }

            counter, ok := this.config["counter"]
            if ok {
                chacha.SetCounter(counter.(uint32))
            }

            dst := make([]byte, len(this.data))

            chacha.XORKeyStream(dst, this.data)

            this.parsedData = dst

            return this
        // 32 bytes
        case "Chacha20poly1305":
            chacha, err := chacha20poly1305.New(this.key)
            if err != nil {
                this.Error = fmt.Errorf("chacha20poly1305.New(),error:%w", err)
                return this
            }

            nonce, ok := this.config["nonce"]
            if !ok {
                this.Error = fmt.Errorf("chacha20poly1305 error: nonce is empty.")
                return this
            }

            additional, _ := this.config["additional"]

            dst, err := chacha.Open(nil, nonce.([]byte), this.data, additional.([]byte))
            if err != nil {
                this.Error = err
                return this
            }

            this.parsedData = dst

            return this
        // RC4 key, at least 1 byte and at most 256 bytes.
        case "RC4":
            rc, err := rc4.NewCipher(this.key)
            if err != nil {
                this.Error = fmt.Errorf("rc4.NewCipher(),error:%w", err)
                return this
            }

            dst := make([]byte, len(this.data))

            rc.XORKeyStream(dst, this.data)

            this.parsedData = dst

            return this
        // Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
        case "Xts":
            cipher, ok := this.config["cipher"]
            if !ok {
                this.Error = fmt.Errorf("Xts error: cipher is empty.")
                return this
            }

            sectorNum, ok := this.config["sector_num"]
            if !ok {
                this.Error = fmt.Errorf("Xts error: sector_num is empty.")
                return this
            }

            cipherFunc := tool.NewCipher().GetFunc(cipher.(string))

            xc, err := xts.NewCipher(cipherFunc, this.key)
            if err != nil {
                this.Error = fmt.Errorf("xts.NewCipher(),error:%w", err)
                return this
            }

            dst := make([]byte, len(this.data))

            xc.Decrypt(dst, this.data, sectorNum.(uint64))

            this.parsedData = this.UnPadding(dst)

            return this
        default:
            this.Error = fmt.Errorf("Multiple [%s] is error.", this.multiple)
            return this
    }
}
