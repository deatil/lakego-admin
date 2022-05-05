package jwt

// JWT
func New() *JWT {
    jwter := &JWT{
        Secret: "123456",
        SigningMethod: "HS256",
        Headers: make(HeaderMap),
        Claims: make(ClaimMap),
        SigningMethods: make(SigningMethodMap),
        SigningFuncs: make(SigningFuncMap),
        ParseFuncs: make(ParseFuncMap),
    }

    // 设置签名方式
    jwter.WithSignMethodMany(signingMethodList)

    return jwter
}

type (
    // jwt 头数据
    HeaderMap = map[string]any

    // jwt 载荷
    ClaimMap = map[string]any

    // 验证方式列表
    SigningMethodMap = map[string]SigningMethod

    // 自定义签名方式
    SigningFuncMap = map[string]func(*JWT) (any, error)

    // 自定义解析方式
    ParseFuncMap = map[string]func(*JWT) (any, error)

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

    // 验证方式列表
    SigningMethods SigningMethodMap

    // 自定义签名方式
    SigningFuncs SigningFuncMap

    // 自定义解析方式
    ParseFuncs ParseFuncMap
}
