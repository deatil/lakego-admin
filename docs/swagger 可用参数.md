## swagger 可用参数.md


### 脚本

~~~cmd
> swag init --output=./docs/swagger --parseDependency --parseDepth=6
~~~


### 可用参数

~~~
--dir=./

--exclude=

--generalInfo=main.go

--propertyStrategy=

--output=./docs

--outputTypes=go,json,yaml

--parseVendor=false

--parseDependency=false

--parseDepth=6

--markdownFiles=

--codeExampleFiles=

--parseInternal=false

--generatedTime=false

--instanceName=

--overridesFile=
~~~

### 其他

~~~
//go:generate go env -w GO111MODULE=on
//go:generate go env -w GOPROXY=https://goproxy.cn,direct
//go:generate go mod tidy
//go:generate go mod download
~~~
