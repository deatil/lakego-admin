module github.com/deatil/lakego-admin

go 1.16

replace (
	app => ./app
	github.com/deatil/go-filesystem => ./pkg/go-filesystem
	github.com/deatil/lakego-doak => ./pkg/lakego-doak
)

require (
	app v0.0.3
	github.com/deatil/lakego-doak v0.0.3
	github.com/fatih/color v1.13.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/ugorji/go v1.2.6 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/exp v0.0.0-20211012155715-ffe10e552389 // indirect
	golang.org/x/image v0.0.0-20210628002857-a66eb6448b8d // indirect
	golang.org/x/text v0.3.7 // indirect
)
