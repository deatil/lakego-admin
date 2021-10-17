module lakego-admin

go 1.16

replace (
	app => ./app
	github.com/deatil/lakego-admin => ./pkg/lakego-admin
)

require (
	app v0.0.2
	github.com/deatil/lakego-admin v0.0.2
)
