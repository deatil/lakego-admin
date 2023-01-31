## 系统默认脚本


### 系统安装脚本

~~~go
go run main.go lakego-admin:install
~~~


### 导入 swagger api路由信息

~~~go
go run main.go lakego-admin:import-apiroute
~~~


### 强制将 jwt 的 refreshToken 放入黑名单

~~~go
go run main.go lakego-admin:passport-logout --refreshToken=[token]
~~~


### 重置账号密码

~~~go
go run main.go lakego-admin:reset-password --name=[name] --password=[password]
~~~


### 重设权限

~~~go
go run main.go lakego-admin:reset-permission
~~~


### 停止 admin 系统服务

~~~go
go run main.go lakego-admin:stop [--pid=12345]
~~~


### 系统版本等信息

~~~go
go run main.go lakego-admin:version
~~~


### 推送文件

~~~go
go run main.go lakego:publish [--force] [--provider=providerName] [--tag=tagname]
~~~


### 执行计划任务

~~~go
go run main.go lakego:schedule
~~~


### 创建软连接

~~~go
go run main.go lakego:storage-link [--force]
~~~
