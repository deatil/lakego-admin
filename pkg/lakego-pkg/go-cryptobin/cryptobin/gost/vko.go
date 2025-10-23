package gost

import (
    "errors"
    "math/big"

    "github.com/deatil/go-cryptobin/pubkey/gost"
)

// KEK
func (this Gost) KEK(ukm any) Gost {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/gost: privateKey empty.")
        return this.AppendError(err)
    }

    if this.publicKey == nil {
        err := errors.New("go-cryptobin/gost: publicKey empty.")
        return this.AppendError(err)
    }

    var ukmData *big.Int

    switch uk := ukm.(type) {
        case []byte:
            ukmData = gost.NewUKM(uk)
        case string:
            ukmData = gost.NewUKM([]byte(uk))
        case *big.Int:
            ukmData = uk
    }

    secretData, err := gost.KEK(this.privateKey, this.publicKey, ukmData)
    if err != nil {
        return this.AppendError(err)
    }

    this.secretData = secretData

    return this
}

// KEK2001
func (this Gost) KEK2001(ukm any) Gost {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/gost: privateKey empty.")
        return this.AppendError(err)
    }

    if this.publicKey == nil {
        err := errors.New("go-cryptobin/gost: publicKey empty.")
        return this.AppendError(err)
    }

    var ukmData *big.Int

    switch uk := ukm.(type) {
        case []byte:
            ukmData = gost.NewUKM(uk)
        case string:
            ukmData = gost.NewUKM([]byte(uk))
        case *big.Int:
            ukmData = uk
    }

    secretData, err := gost.KEK2001(this.privateKey, this.publicKey, ukmData)
    if err != nil {
        return this.AppendError(err)
    }

    this.secretData = secretData

    return this
}

// KEK2012256
func (this Gost) KEK2012256(ukm any) Gost {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/gost: privateKey empty.")
        return this.AppendError(err)
    }

    if this.publicKey == nil {
        err := errors.New("go-cryptobin/gost: publicKey empty.")
        return this.AppendError(err)
    }

    var ukmData *big.Int

    switch uk := ukm.(type) {
        case []byte:
            ukmData = gost.NewUKM(uk)
        case string:
            ukmData = gost.NewUKM([]byte(uk))
        case *big.Int:
            ukmData = uk
    }

    secretData, err := gost.KEK2012256(this.privateKey, this.publicKey, ukmData)
    if err != nil {
        return this.AppendError(err)
    }

    this.secretData = secretData

    return this
}

// KEK2012512
func (this Gost) KEK2012512(ukm any) Gost {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/gost: privateKey empty.")
        return this.AppendError(err)
    }

    if this.publicKey == nil {
        err := errors.New("go-cryptobin/gost: publicKey empty.")
        return this.AppendError(err)
    }

    var ukmData *big.Int

    switch uk := ukm.(type) {
        case []byte:
            ukmData = gost.NewUKM(uk)
        case string:
            ukmData = gost.NewUKM([]byte(uk))
        case *big.Int:
            ukmData = uk
    }

    secretData, err := gost.KEK2012512(this.privateKey, this.publicKey, ukmData)
    if err != nil {
        return this.AppendError(err)
    }

    this.secretData = secretData

    return this
}
