package bootstrap

import (
    exampleProvider "app/example/provider/app"
)

// 例子
func init() {
    AddProvider(func() interface{} {
        return &exampleProvider.ServiceProvider{}
    })
}
