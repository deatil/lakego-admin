module github.com/deatil/lakego-admin

go 1.18

replace (
	app => ./app
	github.com/deatil/go-array => ./pkg/lakego-pkg/go-array
	github.com/deatil/go-cmd => ./pkg/lakego-pkg/go-cmd
	github.com/deatil/go-collection => ./pkg/lakego-pkg/go-collection
	github.com/deatil/go-crc => ./pkg/lakego-pkg/go-crc
	github.com/deatil/go-crc16 => ./pkg/lakego-pkg/go-crc16
	github.com/deatil/go-crc32 => ./pkg/lakego-pkg/go-crc32
	github.com/deatil/go-crc8 => ./pkg/lakego-pkg/go-crc8
	github.com/deatil/go-cryptobin => ./pkg/lakego-pkg/go-cryptobin
	github.com/deatil/go-datebin => ./pkg/lakego-pkg/go-datebin
	github.com/deatil/go-encoding => ./pkg/lakego-pkg/go-encoding
	github.com/deatil/go-event => ./pkg/lakego-pkg/go-event
	github.com/deatil/go-exception => ./pkg/lakego-pkg/go-exception
	github.com/deatil/go-filesystem => ./pkg/lakego-pkg/go-filesystem
	github.com/deatil/go-goch => ./pkg/lakego-pkg/go-goch
	github.com/deatil/go-hash => ./pkg/lakego-pkg/go-hash
	github.com/deatil/go-pipeline => ./pkg/lakego-pkg/go-pipeline
	github.com/deatil/go-sign => ./pkg/lakego-pkg/go-sign
	github.com/deatil/go-tree => ./pkg/lakego-pkg/go-tree
	github.com/deatil/go-validator => ./pkg/lakego-pkg/go-validator
	github.com/deatil/lakego-doak => ./pkg/lakego-pkg/lakego-doak
	github.com/deatil/lakego-doak-action-log => ./pkg/lakego-app/doak-action-log
	github.com/deatil/lakego-doak-admin => ./pkg/lakego-app/doak-admin
	github.com/deatil/lakego-doak-database => ./pkg/lakego-app/doak-database
	github.com/deatil/lakego-doak-monitor => ./pkg/lakego-app/doak-monitor
	github.com/deatil/lakego-doak-statics => ./pkg/lakego-app/doak-statics
	github.com/deatil/lakego-doak-swagger => ./pkg/lakego-app/doak-swagger
	github.com/deatil/lakego-filesystem => ./pkg/lakego-pkg/lakego-filesystem
	github.com/deatil/lakego-jwt => ./pkg/lakego-pkg/lakego-jwt
)

require (
	app v0.0.3
	github.com/deatil/lakego-doak v0.0.3
	github.com/deatil/lakego-doak-action-log v0.0.3
	github.com/deatil/lakego-doak-admin v0.0.3
	github.com/deatil/lakego-doak-database v0.0.3
	github.com/deatil/lakego-doak-statics v0.0.0-00010101000000-000000000000
	github.com/deatil/lakego-doak-swagger v0.0.3
	github.com/swaggo/swag v1.8.0
)

require (
	github.com/AlecAivazis/survey/v2 v2.3.2 // indirect
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/casbin/casbin/v2 v2.37.4 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/deatil/go-cmd v0.0.3 // indirect
	github.com/deatil/go-collection v0.0.0-00010101000000-000000000000 // indirect
	github.com/deatil/go-crc16 v0.0.3 // indirect
	github.com/deatil/go-crc8 v0.0.3 // indirect
	github.com/deatil/go-cryptobin v0.0.3 // indirect
	github.com/deatil/go-datebin v0.0.3 // indirect
	github.com/deatil/go-encoding v0.0.0-00010101000000-000000000000 // indirect
	github.com/deatil/go-event v0.0.3 // indirect
	github.com/deatil/go-exception v0.0.0-00010101000000-000000000000 // indirect
	github.com/deatil/go-filesystem v0.0.3 // indirect
	github.com/deatil/go-goch v0.0.3 // indirect
	github.com/deatil/go-hash v0.0.3 // indirect
	github.com/deatil/go-pipeline v0.0.0-00010101000000-000000000000 // indirect
	github.com/deatil/go-sign v0.0.0-00010101000000-000000000000 // indirect
	github.com/deatil/go-validator v0.0.3 // indirect
	github.com/deatil/lakego-filesystem v0.0.0-00010101000000-000000000000 // indirect
	github.com/deatil/lakego-jwt v0.0.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/flosch/pongo2/v6 v6.0.0 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gin-gonic/gin v1.7.7 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.6 // indirect
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/go-openapi/swag v0.21.1 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.9.0 // indirect
	github.com/go-redis/cache/v8 v8.4.3 // indirect
	github.com/go-redis/redis/extra/rediscmd/v8 v8.11.4 // indirect
	github.com/go-redis/redis/extra/redisotel/v8 v8.11.4 // indirect
	github.com/go-redis/redis/v8 v8.11.4 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.1 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/iancoleman/strcase v0.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.2 // indirect
	github.com/joho/godotenv v1.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/lestrrat/go-file-rotatelogs v0.0.0-20180223000712-d3151e2a480f // indirect
	github.com/lestrrat/go-strftime v0.0.0-20180220042222-ba3bf9c1d042 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mitchellh/mapstructure v1.4.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mojocn/base64Captcha v1.3.5 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/afero v1.6.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/cobra v1.2.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.9.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/swaggo/files v0.0.0-20210815190702-a29dd2bc99b2 // indirect
	github.com/swaggo/gin-swagger v1.4.1 // indirect
	github.com/ugorji/go/codec v1.2.6 // indirect
	github.com/vmihailenco/go-tinylfu v0.2.2 // indirect
	github.com/vmihailenco/msgpack/v5 v5.3.4 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	go.opentelemetry.io/otel v1.0.0 // indirect
	go.opentelemetry.io/otel/trace v1.0.0 // indirect
	go.uber.org/dig v1.13.0 // indirect
	golang.org/x/crypto v0.0.0-20220331220935-ae2d96664a29 // indirect
	golang.org/x/exp v0.0.0-20211012155715-ffe10e552389 // indirect
	golang.org/x/image v0.0.0-20210628002857-a66eb6448b8d // indirect
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20220315194320-039c03cc5b86 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.9 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/ini.v1 v1.63.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gorm.io/driver/mysql v1.1.2 // indirect
	gorm.io/gorm v1.21.16 // indirect
)
