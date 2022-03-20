module github.com/deatil/lakego-admin

go 1.18

replace (
	app => ./app
	github.com/deatil/go-filesystem => ./pkg/go-filesystem
	github.com/deatil/lakego-doak => ./pkg/lakego-doak
	github.com/deatil/lakego-doak-action-log => ./pkg/lakego-app/doak-action-log
	github.com/deatil/lakego-doak-admin => ./pkg/lakego-app/doak-admin
	github.com/deatil/lakego-doak-swagger => ./pkg/lakego-app/doak-swagger
)

require (
	app v0.0.3
	github.com/deatil/lakego-doak v0.0.3
	github.com/deatil/lakego-doak-action-log v0.0.3
	github.com/deatil/lakego-doak-admin v0.0.3
	github.com/deatil/lakego-doak-swagger v0.0.3
	github.com/go-openapi/swag v0.21.1 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/swaggo/swag v1.8.0
	github.com/ugorji/go v1.2.6 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/exp v0.0.0-20211012155715-ffe10e552389 // indirect
	golang.org/x/image v0.0.0-20210628002857-a66eb6448b8d // indirect
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f // indirect
	golang.org/x/tools v0.1.9 // indirect
)
