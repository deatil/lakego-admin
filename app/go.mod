module app

go 1.16

replace github.com/deatil/lakego-admin => ./../pkg/lakego-admin

require (
	github.com/deatil/lakego-admin v0.0.0-00010101000000-000000000000
	github.com/gin-gonic/gin v1.7.2
	github.com/spf13/cobra v1.2.1
)
