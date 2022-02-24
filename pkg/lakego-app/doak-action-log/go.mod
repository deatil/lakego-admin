module github.com/deatil/lakego-doak-action-log

go 1.16

replace (
	github.com/deatil/lakego-doak => ./../../lakego-doak
	github.com/deatil/lakego-doak-admin => ./../doak-admin
)

require (
	github.com/deatil/lakego-doak v0.0.3
	github.com/deatil/lakego-doak-admin v0.0.3
)
