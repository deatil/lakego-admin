module github.com/deatil/lakego-admin

go 1.20

replace (
	app => ./app
	extension => ./extension
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
	github.com/deatil/lakego-filesystem => ./pkg/lakego-pkg/lakego-filesystem
	github.com/deatil/lakego-jwt => ./pkg/lakego-pkg/lakego-jwt
	github.com/deatil/lakego-doak => ./pkg/lakego-pkg/lakego-doak
	github.com/deatil/lakego-doak-action-log => ./pkg/lakego-app/doak-action-log
	github.com/deatil/lakego-doak-admin => ./pkg/lakego-app/doak-admin
	github.com/deatil/lakego-doak-extension => ./pkg/lakego-app/doak-extension
	github.com/deatil/lakego-doak-database => ./pkg/lakego-app/doak-database
	github.com/deatil/lakego-doak-devtool => ./pkg/lakego-app/doak-devtool
	github.com/deatil/lakego-doak-monitor => ./pkg/lakego-app/doak-monitor
	github.com/deatil/lakego-doak-statics => ./pkg/lakego-app/doak-statics
	github.com/deatil/lakego-doak-swagger => ./pkg/lakego-app/doak-swagger
)

require (
	app v0.0.3
	extension v0.0.3
	github.com/deatil/lakego-doak v1.0.1002
	github.com/deatil/lakego-doak-admin v1.0.0
	github.com/deatil/lakego-doak-extension v0.0.3
	github.com/deatil/lakego-doak-action-log v0.0.3
	github.com/deatil/lakego-doak-database v0.0.3
	github.com/deatil/lakego-doak-devtool v0.0.3
	github.com/deatil/lakego-doak-monitor v0.0.3
	github.com/deatil/lakego-doak-statics v0.0.3
	github.com/deatil/lakego-doak-swagger v0.0.3
	github.com/swaggo/swag v1.8.12
)

require (
	github.com/deatil/go-array v1.0.1010 // indirect
	github.com/deatil/go-crc v1.0.10006 // indirect
	github.com/deatil/go-crc32 v1.0.10006 // indirect
	github.com/deatil/go-tree v1.0.1001 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/pelletier/go-toml/v2 v2.0.7 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/deatil/go-cryptobin v1.0.2042
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/AlecAivazis/survey/v2 v2.3.6 // indirect
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.1 // indirect
	github.com/bytedance/sonic v1.8.7 // indirect
	github.com/casbin/casbin/v2 v2.66.3 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/deatil/go-cmd v0.0.3 // indirect
	github.com/deatil/go-collection v0.0.0-00010101000000-000000000000 // indirect
	github.com/deatil/go-crc16 v1.0.10005 // indirect
	github.com/deatil/go-crc8 v1.0.10005 // indirect
	github.com/deatil/go-cryptobin v1.0.2001 // indirect
	github.com/deatil/go-datebin v1.0.1013 // indirect
	github.com/deatil/go-encoding v1.0.2003 // indirect
	github.com/deatil/go-event v1.0.1007 // indirect
	github.com/deatil/go-exception v1.0.1002 // indirect
	github.com/deatil/go-filesystem v1.0.6 // indirect
	github.com/deatil/go-goch v1.0.1006 // indirect
	github.com/deatil/go-hash v1.0.2005 // indirect
	github.com/deatil/go-pipeline v1.0.1005 // indirect
	github.com/deatil/go-sign v1.0.1001 // indirect
	github.com/deatil/go-validator v0.0.3 // indirect
	github.com/deatil/lakego-filesystem v1.0.1007 // indirect
	github.com/deatil/lakego-jwt v1.0.1005 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/flosch/pongo2/v6 v6.0.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gin-gonic/gin v1.9.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/spec v0.20.8 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.12.0 // indirect
	github.com/go-redis/cache/v8 v8.4.4 // indirect
	github.com/go-redis/redis/extra/rediscmd/v8 v8.11.5 // indirect
	github.com/go-redis/redis/extra/redisotel/v8 v8.11.5 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/iancoleman/strcase v0.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/compress v1.16.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.4 // indirect
	github.com/leodido/go-urn v1.2.3 // indirect
	github.com/lestrrat/go-file-rotatelogs v0.0.0-20180223000712-d3151e2a480f // indirect
	github.com/lestrrat/go-strftime v0.0.0-20180220042222-ba3bf9c1d042 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.18 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mojocn/base64Captcha v1.3.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/rogpeppe/go-internal v1.8.0 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/cobra v1.7.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.15.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/swaggo/files v1.0.1 // indirect
	github.com/swaggo/gin-swagger v1.6.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	github.com/vmihailenco/go-tinylfu v0.2.2 // indirect
	github.com/vmihailenco/msgpack/v5 v5.3.5 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	go.opentelemetry.io/otel v1.14.0 // indirect
	go.opentelemetry.io/otel/trace v1.14.0 // indirect
	go.uber.org/dig v1.16.1 // indirect
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/crypto v0.8.0 // indirect
	golang.org/x/image v0.7.0 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	golang.org/x/term v0.7.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/tools v0.8.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gorm.io/driver/mysql v1.4.7 // indirect
	gorm.io/gorm v1.24.6 // indirect
)
