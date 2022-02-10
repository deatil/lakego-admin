module app

go 1.16

replace github.com/deatil/lakego-doak => ./../pkg/lakego-doak

require (
	github.com/deatil/lakego-doak v0.0.0-00010101000000-000000000000
	github.com/gin-gonic/gin v1.7.2
	github.com/spf13/cobra v1.2.1
)
