package provider

import (
    "github.com/gin-gonic/gin"
)

/**
 * 服务提供者接口
 *
 * @create 2021-6-19
 * @author deatil
 */
type ServiceProvider interface {
    // 设置 App
    WithRoute(*gin.Engine)
    
    // 注册
    Register()  
    
    // 引导
    Boot() 
}