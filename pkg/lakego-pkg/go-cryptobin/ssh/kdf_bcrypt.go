package ssh

import (
    "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/kdf/bcrypt_pbkdf"
)

var (
    bcryptName = "bcrypt"
)

// 设置
type bcryptOpts struct {
    Salt   string
    Rounds uint32
}

// bcrypt 数据
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

// BcryptOpts 设置
type BcryptOpts struct {
    SaltSize int
    Rounds   int
}

func (this BcryptOpts) DeriveKey(password []byte, size int) ([]byte, string, error) {
    salt, err := genRandom(this.SaltSize)
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
        Salt: string(salt),
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
