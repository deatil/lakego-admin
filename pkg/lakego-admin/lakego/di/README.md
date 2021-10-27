### 使用

~~~go
import (
    "github.com/deatil/lakego-admin/lakego/di"
    "github.com/deatil/lakego-admin/lakego/facade/config"
)

// 添加
di.New().Provide(func() *config.Config {
    return config.New()
})

// 使用获取
var data2 string
di.New().Invoke(func(conf *config.Config) {
    data2 = conf.Use("auth").GetString("Passport.PasswordSalt")
})
~~~

