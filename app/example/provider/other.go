package provider

import (
    "fmt"

    "github.com/deatil/lakego-doak/lakego/provider"
)

/**
 * 服务提供者例子
 *
 * @create 2021-10-12
 * @author deatil
 */
type OtherServiceProvider struct {
    provider.ServiceProvider
}

// 注册
func (this *OtherServiceProvider) Register() {
    if !this.GetApp().RunningInConsole() {
        fmt.Println("例子 Register 注册")
    }
}

/**
 * 引导
 */
func (this *OtherServiceProvider) Boot() {
    if !this.GetApp().RunningInConsole() {
        fmt.Println("例子 Boot 引导")
    }
}
