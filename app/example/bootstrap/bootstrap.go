package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    exampleProvider "app/example/provider/app"
)

// 例子
func init() {
    kernel.AddProvider(func() interface{} {
        return &exampleProvider.ServiceProvider{}
    })
}
