package cryptobin

import (
    "fmt"
    "crypto/rc4"

    "golang.org/x/crypto/chacha20"
    "golang.org/x/crypto/chacha20poly1305"
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
        default:
            this.Error = fmt.Errorf("Multiple [%s] is error.", this.multiple)
            return this
    }
}
