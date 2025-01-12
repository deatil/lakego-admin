### PKCS8 使用文档


#### 包引入 / import pkcs8
~~~go
import (
    "github.com/deatil/go-cryptobin/pkcs8"
)
~~~


#### 加密私钥证书 / Encrypt Private Key

~~~go
import (
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pkcs8"
)

func main() {
    var prikey []byte = []byte("...")
    var pass []byte = []byte("...")

    // 默认设置 / default options
    var opts = pkcs8.DefaultOpts

    // 可用默认设置 / can use default options:
    // DefaultPBKDF2Opts | DefaultSMPBKDF2Opts | DefaultScryptOpts | DefaultOpts | DefaultSMOpts
    block, err := pkcs8.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", prikey, pass, opts)

    // 自定义设置
    // use struct to make options
    var opts1 = pkcs8.Opts{
        Cipher:  pkcs8.SM4CBC,
        KDFOpts: pkcs8.SMPBKDF2Opts{
            SaltSize:       8,
            IterationCount: 5000,
            HMACHash:       pkcs8.DefaultSMHash,
        },
    }
    var opts2 = pkcs8.Opts{
        Cipher:  pkcs8.AES256CBC,
        KDFOpts: pkcs8.PBKDF2Opts{
            SaltSize:       16,
            IterationCount: 10000,
        },
    }
    var opts3 = pkcs8.Opts{
        Cipher:  pkcs8.AES256CBC,
        KDFOpts: pkcs8.PBKDF2Opts{
            SaltSize:       16,
            IterationCount: 10000,
            // HMACHash:    pkcs8.DefaultHash
            HMACHash:       pkcs8.GetHashFromName("SHA256"),
        },
    }
    var opts4 = pkcs8.Opts{
        Cipher:  pkcs8.AES256CBC,
        KDFOpts: pkcs8.ScryptOpts{
            SaltSize:                 16,
            CostParameter:            1 << 2,
            BlockSize:                8,
            ParallelizationParameter: 1,
        },
    }
    var opts5 = pkcs8.Opts{
        Cipher:  pkcs8.AES256CBC,
        KDFOpts: pkcs8.DefaultPBKDF2Opts,
    }

    // 使用铺助函数生成设置
    // use helper function to get options
    opts, err := pkcs8.MakeOpts("AES256CBC", "SHA256")
    opts, err := pkcs8.MakeOpts(pkcs8.AES256CBC, pkcs8.SHA256)
    opts, err := pkcs8.MakeOpts(pkcs8.SHA1AndDES)

}
~~~


#### 解密已加密私钥证书 / Decrypt encrypted Private Key

~~~go
import (
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
)

func main() {
    var pemkey []byte = []byte("...")
    var password []byte = []byte("...")

    block, _ := pem.Decode(pemkey)

    dekey, err := pkcs8.DecryptPEMBlock(block, password)
    if err != nil {
        // return error
    }
}
