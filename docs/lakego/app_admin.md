## 系统脚手架文档


### 生成控制器

运行命令后将会在目录 `app/admin/controller` 生成代码文件 `hot_book.go`

~~~go
go run main.go lakego-admin:app-admin --type=create_controller --name=HotBook
go run main.go lakego-admin:app-admin --type=create_controller --name=HotBook --force
~~~


### 生成模型

运行命令后将会在目录 `app/admin/model` 生成代码文件 `hot_book.go`

~~~go
go run main.go lakego-admin:app-admin --type=create_model --name=HotBook
go run main.go lakego-admin:app-admin --type=create_model --name=HotBook --force
~~~
