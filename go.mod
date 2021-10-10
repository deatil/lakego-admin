module lakego-admin

go 1.16

replace (
	github.com/deatil/lakego-admin => ./pkg/lakego-admin
	app => ./app
)

require (
	github.com/deatil/lakego-admin v0.0.2 // indirect
	app v0.0.2 // indirect
)
