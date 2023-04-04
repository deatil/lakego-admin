package jwt

// 构造函数
func NewConfig(
    secret string,
    privateKey []byte,
    publicKey []byte,
    privateKeyPassword string,
) Config {
    return Config{
        secret,
        privateKey,
        publicKey,
        privateKeyPassword,
    }
}

// 配置信息
type Config struct {
    // 秘钥
    secret string

    // 私钥
    privateKey []byte

    // 公钥
    publicKey []byte

    // 私钥密码
    privateKeyPassword string
}

func (this Config) Secret() string {
    return this.secret
}

func (this Config) PrivateKey() []byte {
    return this.privateKey
}

func (this Config) PublicKey() []byte {
    return this.publicKey
}

func (this Config) PrivateKeyPassword() string {
    return this.privateKeyPassword
}
