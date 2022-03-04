module github.com/deatil/lakego-doak-swagger

go 1.16

replace (
	github.com/deatil/lakego-doak => ./../../lakego-doak
	github.com/deatil/lakego-doak-admin => ./../doak-admin
)

require (
	github.com/deatil/lakego-doak v0.0.3
	github.com/deatil/lakego-doak-admin v0.0.3
	github.com/swaggo/files v0.0.0-20210815190702-a29dd2bc99b2 // indirect
	github.com/swaggo/gin-swagger v1.4.1 // indirect
)
