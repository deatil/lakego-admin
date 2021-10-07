## lakego-admin 后台管理系统


### 项目介绍

*  `lakego-admin` 是基于 `gin` 的后台开发框架，完全api接口化，适用于前后端分离的项目
*  基于 `JWT` 的用户登录态管理
*  权限判断基于 `go-casbin` 的 `RBAC` 授权
*  本项目为 `后台api服务`


### 环境要求

 - Go >= 1.15
 - Gorm >= v1.21.10
 - Redis


### 截图预览

<table>
    <tr>
        <td width="50%">
            <center>
                <img alt="login" src="" />
            </center>
        </td>
        <td width="50%">
            <center>
                <img alt="index" src="" />
            </center>
        </td>
    </tr>
</table>


### 安装步骤

1. 首先克隆项目到本地

```
git clone git@github.com:deatil/lakego-admin.git
```

2. 然后配置数据库等相关配置，配置位置

```
/config
```

3. 最后运行下面的命令安装系统

```go
go run main.go lakego-admin:install
```

4. 权限规则导入，并且你需要自己修改导入的规则层级

```go
go run main.go lakego-admin:import-route
```

5. 后台登录账号及密码：`admin` / `123456`


### 特别鸣谢

感谢以下的项目,排名不分先后

 - github.com/gin-gonic/gin

 - gorm.io/gorm

 - github.com/golang-jwt/jwt

 - github.com/casbin/casbin

 - github.com/spf13/cobra

 - github.com/go-redis/redis


### 开源协议

*  `lakego-admin` 遵循 `Apache2` 开源协议发布，在保留本系统版权的情况下提供个人及商业免费使用。


### 版权

*  该系统所属版权归 deatil(https://github.com/deatil) 所有。
