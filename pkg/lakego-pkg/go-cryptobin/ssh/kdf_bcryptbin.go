package ssh

import (
    "io"
    "bytes"
    "errors"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/kdf/bcrypt_pbkdf"
)

var (
    bcryptbinName = "bcryptbin"
)

// bcryptbin Params
type bcryptbinParams struct {}

func (this bcryptbinParams) DeriveKey(password []byte, kdfOpts string, size int) (key []byte, err error) {
    salt, rounds, err := parseBcryptKdfOpts(kdfOpts)
    if err != nil {
        return nil, err
    }

    return bcrypt_pbkdf.Key(
        password, salt,
        int(rounds), size,
    )
}

func parseBcryptKdfOpts(kdfOpts string) ([]byte, uint32, error) {
    // Read kdf options.
    buf := bytes.NewReader([]byte(kdfOpts))

    var saltLength uint32
    if err := binary.Read(buf, binary.BigEndian, &saltLength); err != nil {
        return nil, 0, errors.New("cannot decode encrypted private keys: bad format")
    }

    salt := make([]byte, saltLength)
    if err := binary.Read(buf, binary.BigEndian, &salt); err != nil {
        return nil, 0, errors.New("cannot decode encrypted private keys: bad format")
    }

    var rounds uint32
    if err := binary.Read(buf, binary.BigEndian, &rounds); err != nil {
        return nil, 0, errors.New("cannot decode encrypted private keys: bad format")
    }

    return salt, rounds, nil
}

// BcryptbinOpts options
type BcryptbinOpts struct {
    SaltSize int
    Rounds   int
}

func (this BcryptbinOpts) DeriveKey(random io.Reader, password []byte, size int) (key []byte, params string, err error) {
    salt := make([]byte, this.SaltSize)
    _, err = io.ReadFull(random, salt)
    if err != nil {
        return nil, "", err
    }

    key, err = bcrypt_pbkdf.Key(
        password, salt,
        this.Rounds, size,
    )
    if err != nil {
        return nil, "", err
    }

    buf := new(bytes.Buffer)
    binary.Write(buf, binary.BigEndian, uint32(this.SaltSize))
    binary.Write(buf, binary.BigEndian, salt)
    binary.Write(buf, binary.BigEndian, uint32(this.Rounds))
    params = buf.String()

    return key, params, nil
}

func (this BcryptbinOpts) GetSaltSize() int {
    return this.SaltSize
}

func (this BcryptbinOpts) Name() string {
    return bcryptbinName
}

func init() {
    AddKDF(bcryptbinName, func() KDFParameters {
        return new(bcryptbinParams)
    })
}
