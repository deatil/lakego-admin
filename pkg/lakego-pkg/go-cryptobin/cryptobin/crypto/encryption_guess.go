package crypto

import (
    "fmt"
    "crypto/rc4"

    "golang.org/x/crypto/xts"
    "golang.org/x/crypto/chacha20"
    "golang.org/x/crypto/chacha20poly1305"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 加密
func (this Cryptobin) GuessEncrypt() Cryptobin {
    switch this.multiple {
        // 32 bytes key and a 12 or 24 bytes nonce
        case Chacha20:
            if !this.config.Has("nonce") {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] chacha20 error: nonce is empty.")
                return this.AppendError(err)
            }

            nonce := this.config.GetBytes("nonce")

            chacha, err := chacha20.NewUnauthenticatedCipher(this.key, nonce)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] chacha20.New(),error:%w", err)
                return this.AppendError(err)
            }

            if this.config.Has("counter") {
                chacha.SetCounter(this.config.GetUint32("counter"))
            }

            dst := make([]byte, len(this.data))

            chacha.XORKeyStream(dst, this.data)

            this.parsedData = dst

            return this
        // 32 bytes
        case Chacha20poly1305:
            aead, err := chacha20poly1305.New(this.key)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] chacha20poly1305.New(),error:%w", err)
                return this.AppendError(err)
            }

            if !this.config.Has("nonce") {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] chacha20poly1305 error: nonce is empty.")
                return this.AppendError(err)
            }

            nonce := this.config.GetBytes("nonce")
            additional := this.config.GetBytes("additional")

            this.parsedData = aead.Seal(nil, nonce, this.data, additional)

            return this
        // 32 bytes
        case Chacha20poly1305X:
            aead, err := chacha20poly1305.NewX(this.key)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] chacha20poly1305.NewX(),error:%w", err)
                return this.AppendError(err)
            }

            if !this.config.Has("nonce") {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] chacha20poly1305 error: nonce is empty.")
                return this.AppendError(err)
            }

            nonce := this.config.GetBytes("nonce")
            additional := this.config.GetBytes("additional")

            this.parsedData = aead.Seal(nil, nonce, this.data, additional)

            return this
        // RC4 key, at least 1 byte and at most 256 bytes.
        case RC4:
            rc, err := rc4.NewCipher(this.key)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] rc4.NewCipher(),error:%w", err)
                return this.AppendError(err)
            }

            dst := make([]byte, len(this.data))

            rc.XORKeyStream(dst, this.data)

            this.parsedData = dst

            return this
        // Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
        case Xts:
            if !this.config.Has("cipher") {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] Xts error: cipher is empty.")
                return this.AppendError(err)
            }

            if !this.config.Has("sector_num") {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] Xts error: sector_num is empty.")
                return this.AppendError(err)
            }

            cipher := this.config.GetString("cipher")
            sectorNum := this.config.GetUint64("sector_num")

            cipherFunc := cryptobin_tool.NewCipher().GetFunc(cipher)

            xc, err := xts.NewCipher(cipherFunc, this.key)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessEncrypt()] xts.NewCipher(),error:%w", err)
                return this.AppendError(err)
            }

            // 大小
            bs := 16

            plainPadding := this.Padding(this.data, bs)

            dst := make([]byte, len(plainPadding))

            xc.Encrypt(dst, plainPadding, sectorNum)

            this.parsedData = dst

            return this
        default:
            err := fmt.Errorf("Cryptobin: [GuessEncrypt()] Multiple [%s] is error.", this.multiple)
            return this.AppendError(err)
    }
}

// 解密
func (this Cryptobin) GuessDecrypt() Cryptobin {
    switch this.multiple {
        // 32 bytes key and a 12 or 24 bytes nonce
        case Chacha20:
            if !this.config.Has("nonce") {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] chacha20 error: nonce is empty.")
                return this.AppendError(err)
            }

            nonce := this.config.GetBytes("nonce")

            chacha, err := chacha20.NewUnauthenticatedCipher(this.key, nonce)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] chacha20.New(),error:%w", err)
                return this.AppendError(err)
            }

            if this.config.Has("counter") {
                chacha.SetCounter(this.config.GetUint32("counter"))
            }

            dst := make([]byte, len(this.data))

            chacha.XORKeyStream(dst, this.data)

            this.parsedData = dst

            return this
        // 32 bytes
        case Chacha20poly1305:
            chacha, err := chacha20poly1305.New(this.key)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] chacha20poly1305.New(),error:%w", err)
                return this.AppendError(err)
            }

            if !this.config.Has("nonce") {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] chacha20poly1305 error: nonce is empty.")
                return this.AppendError(err)
            }

            nonce := this.config.GetBytes("nonce")
            additional := this.config.GetBytes("additional")

            dst, err := chacha.Open(nil, nonce, this.data, additional)
            if err != nil {
                return this.AppendError(err)
            }

            this.parsedData = dst

            return this
        // 32 bytes
        case Chacha20poly1305X:
            chacha, err := chacha20poly1305.NewX(this.key)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] chacha20poly1305.NewX(),error:%w", err)
                return this.AppendError(err)
            }

            if !this.config.Has("nonce") {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] chacha20poly1305 error: nonce is empty.")
                return this.AppendError(err)
            }

            nonce := this.config.GetBytes("nonce")
            additional := this.config.GetBytes("additional")

            dst, err := chacha.Open(nil, nonce, this.data, additional)
            if err != nil {
                return this.AppendError(err)
            }

            this.parsedData = dst

            return this
        // RC4 key, at least 1 byte and at most 256 bytes.
        case RC4:
            rc, err := rc4.NewCipher(this.key)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] rc4.NewCipher(),error:%w", err)
                return this.AppendError(err)
            }

            dst := make([]byte, len(this.data))

            rc.XORKeyStream(dst, this.data)

            this.parsedData = dst

            return this
        // Sectors must be a multiple of 16 bytes and less than 2²⁴ bytes.
        case Xts:
            if !this.config.Has("cipher") {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] Xts error: cipher is empty.")
                return this.AppendError(err)
            }

            if !this.config.Has("sector_num") {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] Xts error: sector_num is empty.")
                return this.AppendError(err)
            }

            cipher := this.config.GetString("cipher")
            sectorNum := this.config.GetUint64("sector_num")

            cipherFunc := cryptobin_tool.NewCipher().GetFunc(cipher)

            xc, err := xts.NewCipher(cipherFunc, this.key)
            if err != nil {
                err := fmt.Errorf("Cryptobin: [GuessDecrypt()] xts.NewCipher(),error:%w", err)
                return this.AppendError(err)
            }

            dst := make([]byte, len(this.data))

            xc.Decrypt(dst, this.data, sectorNum)

            this.parsedData = this.UnPadding(dst)

            return this
        default:
            err := fmt.Errorf("Cryptobin: [GuessDecrypt()] Multiple [%s] is error.", this.multiple)
            return this.AppendError(err)
    }
}
