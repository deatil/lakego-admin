package ssh

import (
    "io"

    "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/kdf/bcrypt_pbkdf"
)

var (
    bcryptName = "bcrypt"
)

// bcrypt options struct
type bcryptOpts struct {
    Salt   string
    Rounds uint32
}

// bcrypt params
type bcryptParams struct {}

func (this bcryptParams) DeriveKey(password []byte, kdfOpts string, size int) ([]byte, error) {
    var opts bcryptOpts
    if err := ssh.Unmarshal([]byte(kdfOpts), &opts); err != nil {
        return nil, err
    }

    return bcrypt_pbkdf.Key(
        password, []byte(opts.Salt),
        int(opts.Rounds), size,
    )
}

// BcryptOpts options
type BcryptOpts struct {
    SaltSize int
    Rounds   int
}

func (this BcryptOpts) DeriveKey(random io.Reader, password []byte, size int) ([]byte, string, error) {
    salt := make([]byte, this.SaltSize)
    _, err := io.ReadFull(random, salt)
    if err != nil {
        return nil, "", err
    }

    key, err := bcrypt_pbkdf.Key(
        password, salt,
        this.Rounds, size,
    )
    if err != nil {
        return nil, "", err
    }

    params := ssh.Marshal(bcryptOpts{
        Salt:   string(salt),
        Rounds: uint32(this.Rounds),
    })

    return key, string(params), nil
}

func (this BcryptOpts) GetSaltSize() int {
    return this.SaltSize
}

func (this BcryptOpts) Name() string {
    return bcryptName
}

func init() {
    AddKDF(bcryptName, func() KDFParameters {
        return new(bcryptParams)
    })
}
