package code

// 常量
const (
    // 常用业务状态码
    StatusSuccess   int = 0
    StatusError     int = 1
    StatusException int = 99997
    StatusUnknown   int = 99998
    StatusInvalid   int = 99999

    LoginError  int = 100100
    LogoutError int = 100101
    AuthError   int = 100102

    // token相关
    JwtTokenOK          int = 200100 // token 有效
    JwtTokenInvalid     int = 200101 // 无效的 token
    JwtTokenExpired     int = 200102 // 过期的 token
    JwtTokenFormatErr   int = 200103 // 提交的 token 格式错误
    JwtAccessTokenFail  int = 200204
    JwtRefreshTokenFail int = 200205

    // Curd
    FileSaveFailed int = 300100
    RecordNotFound int = 300101
    DeleteFailed   int = 300102
    CreateFailed   int = 300103
    UpdateFailed   int = 300104
    ParamError     int = 300105
)
