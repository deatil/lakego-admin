package provider

import (
    "github.com/deatil/lakego-admin/lakego/kernel"

    exampleProvider "app/example/provider/app"
)

// 例子
func init() {
    kernel.AddProvider(func() interface{} {
        return &exampleProvider.ServiceProvider{}
    })
}
