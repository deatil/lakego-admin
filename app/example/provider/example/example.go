package example

import (
    "fmt"

    "github.com/deatil/lakego-admin/lakego/provider"
)

/**
 * 服务提供者例子
 *
 * @create 2021-10-12
 * @author deatil
 */
type ServiceProvider struct {
    provider.ServiceProvider
}

// 注册
func (s *ServiceProvider) Register() {
    if !s.GetApp().RunningInConsole() {
        fmt.Println("例子 Register 注册")
    }
}

/**
 * 引导
 */
func (s *ServiceProvider) Boot() {
    if !s.GetApp().RunningInConsole() {
        fmt.Println("例子 Boot 引导")
    }
}
