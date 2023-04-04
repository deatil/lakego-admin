package jwt

// JWT
func New(opts ...Option) *JWT {
    j := &JWT{
        Secret: "123456",
        SigningMethod: "HS256",
        Headers: make(HeaderMap),
        Claims:  make(ClaimMap),
    }

    for _, opt := range opts {
        opt(j)
    }

    return j
}

type (
    // jwt 头数据
    HeaderMap = map[string]any

    // jwt 载荷
    ClaimMap = map[string]any

    // jwt 解析后的头数据 map
    ParsedHeaderMap = map[string]any
)

/**
 * JWT
 *
 * @create 2021-9-15
 * @author deatil
 */
type JWT struct {
    // 头数据
    Headers HeaderMap

    // 载荷
    Claims ClaimMap

    // 签名方法
    SigningMethod string

    // 秘钥
    Secret string

    // 私钥
    PrivateKey []byte

    // 公钥
    PublicKey []byte

    // 私钥密码
    PrivateKeyPassword string
}
