package config

// 配置信息
type SignerConfig struct {
    // 秘钥
    Secret string

    // 私钥
    PrivateKey []byte

    // 公钥
    PublicKey []byte

    // 私钥密码
    PrivateKeyPassword string
}
