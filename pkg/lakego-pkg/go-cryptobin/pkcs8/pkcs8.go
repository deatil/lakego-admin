package pkcs8

import (
    "io"
    "fmt"
    "hash"
    "errors"
    "crypto/md5"
    "crypto/aes"
    "crypto/des"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/x509"
    "crypto/x509/pkix"
    "crypto/cipher"
    "encoding/asn1"
    "encoding/pem"

    "golang.org/x/crypto/pbkdf2"
)

// PBKDF2SaltSize is the default size of the salt for PBKDF2, 128-bit salt.
const PBKDF2SaltSize = 16

// PBKDF2Iterations is the default number of iterations for PBKDF2, 100k
// iterations. Nist recommends at least 10k, 1Passsword uses 100k.
const PBKDF2Iterations = 10000

// 结构体数据可以查看以下文档
// RFC5208 at https://tools.ietf.org/html/rfc5208
// RFC5958 at https://tools.ietf.org/html/rfc5958
type encryptedPrivateKeyInfo struct {
    EncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedData       []byte
}

// pbes2 数据
type pbes2Params struct {
    KeyDerivationFunc pkix.AlgorithmIdentifier
    EncryptionScheme  pkix.AlgorithmIdentifier
}

// pbkdf2 数据
type pbkdf2Params struct {
    Salt           []byte
    IterationCount int
    PrfParam       pkix.AlgorithmIdentifier `asn1:"optional"`
}

var (
    // key derivation functions
    oidRSADSI         = asn1.ObjectIdentifier{1, 2, 840, 113549}
    oidPKCS5          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5}
    oidPKCS5PBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
    oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

    // hash 方式
    oidDigestAlgorithm     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2}
    oidHMACWithMD5         = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
    oidHMACWithSHA1        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
    oidHMACWithSHA224      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
    oidHMACWithSHA256      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
    oidHMACWithSHA384      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
    oidHMACWithSHA512      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
    oidHMACWithSHA512_224  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 12}
    oidHMACWithSHA512_256  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 13}

    // 加密方式
    oidEncryptionAlgorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 3}
    oidDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
    oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}

    oidAES       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1}
    oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
    oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
    oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// HMAC 列表
var oidAsn1s = map[string]asn1.ObjectIdentifier{
    "MD5":        oidHMACWithMD5,
    "SHA1":       oidHMACWithSHA1,
    "SHA224":     oidHMACWithSHA224,
    "SHA256":     oidHMACWithSHA256,
    "SHA384":     oidHMACWithSHA384,
    "SHA512":     oidHMACWithSHA512,
    "SHA512_224": oidHMACWithSHA512_224,
    "SHA512_256": oidHMACWithSHA512_256,
}

// hash 列表
var oidHashs = map[string]func() hash.Hash{
    "MD5":        md5.New,
    "SHA1":       sha1.New,
    "SHA224":     sha256.New224,
    "SHA256":     sha256.New,
    "SHA384":     sha512.New384,
    "SHA512":     sha512.New,
    "SHA512_224": sha512.New512_224,
    "SHA512_256": sha512.New512_256,
}

// 配置
type Opts struct {
    SaltSize       int
    IterationCount int
    HMACHash       string
}

// 默认配置
var DefaultOpts = &Opts{
    SaltSize:       PBKDF2SaltSize,
    IterationCount: PBKDF2Iterations,
    HMACHash:       "SHA256",
}

// PEM 块
type rfc1423Algo struct {
    cipher     x509.PEMCipher
    name       string
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    blockSize  int
    identifier asn1.ObjectIdentifier
}

// 生成 pbkdf2 值
func (this rfc1423Algo) deriveKey(password, salt []byte, iterationCount int, h func() hash.Hash) []byte {
    return pbkdf2.Key(password, salt, iterationCount, this.keySize, h)
}

// PEM 块列表
var rfc1423Algos = []rfc1423Algo{
    {
        cipher:     x509.PEMCipherDES,
        name:       "DES-CBC",
        cipherFunc: des.NewCipher,
        keySize:    8,
        blockSize:  des.BlockSize,
        identifier: oidDESCBC,
    },
    {
        cipher:     x509.PEMCipher3DES,
        name:       "DES-EDE3-CBC",
        cipherFunc: des.NewTripleDESCipher,
        keySize:    24,
        blockSize:  des.BlockSize,
        identifier: oidDESEDE3CBC,
    },
    {
        cipher:     x509.PEMCipherAES128,
        name:       "AES-128-CBC",
        cipherFunc: aes.NewCipher,
        keySize:    16,
        blockSize:  aes.BlockSize,
        identifier: oidAES128CBC,
    },
    {
        cipher:     x509.PEMCipherAES192,
        name:       "AES-192-CBC",
        cipherFunc: aes.NewCipher,
        keySize:    24,
        blockSize:  aes.BlockSize,
        identifier: oidAES192CBC,
    },
    {
        cipher:     x509.PEMCipherAES256,
        name:       "AES-256-CBC",
        cipherFunc: aes.NewCipher,
        keySize:    32,
        blockSize:  aes.BlockSize,
        identifier: oidAES256CBC,
    },
}

// 最加数据为新的 Identifier
func AppendOID(b asn1.ObjectIdentifier, v ...int) asn1.ObjectIdentifier {
    n := make(asn1.ObjectIdentifier, len(b), len(b) + len(v))
    copy(n, b)
    return append(n, v...)
}

// 添加 oidAsn1
func AddOidAsn1(name string, identifier asn1.ObjectIdentifier) {
    if _, ok := oidAsn1s[name]; ok {
        delete(oidAsn1s, name)
    }

    oidAsn1s[name] = identifier
}

// 添加 oidHash
func AddOidHash(name string, value func() hash.Hash) {
    if _, ok := oidHashs[name]; ok {
        delete(oidHashs, name)
    }

    oidHashs[name] = value
}

// 添加 rfc1423Algo
func AddRfc1423Algo(value rfc1423Algo) {
    rfc1423Algos = append(rfc1423Algos, value)
}

// 返回使用的 Hash 方式
func prfByOID(oid asn1.ObjectIdentifier) func() hash.Hash {
    if len(oid) == 0 {
        return md5.New
    }

    if oid.Equal(oidHMACWithMD5) {
        return md5.New
    }
    if oid.Equal(oidHMACWithSHA1) {
        return sha1.New
    }
    if oid.Equal(oidHMACWithSHA224) {
        return sha256.New224
    }
    if oid.Equal(oidHMACWithSHA256) {
        return sha256.New
    }
    if oid.Equal(oidHMACWithSHA384) {
        return sha512.New384
    }
    if oid.Equal(oidHMACWithSHA512) {
        return sha512.New
    }
    if oid.Equal(oidHMACWithSHA512_224) {
        return sha512.New512_224
    }
    if oid.Equal(oidHMACWithSHA512_256) {
        return sha512.New512_256
    }

    return nil
}

func cipherByKey(key x509.PEMCipher) *rfc1423Algo {
    for i := range rfc1423Algos {
        alg := &rfc1423Algos[i]
        if alg.cipher == key {
            return alg
        }
    }
    return nil
}

// 解出 PEM 块
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
    if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
        return x509.DecryptPEMBlock(block, password)
    }

    // PKCS#8 header defined in RFC7468 section 11
    if block.Type == "ENCRYPTED PRIVATE KEY" {
        return DecryptPKCS8PrivateKey(block.Bytes, password)
    }

    return nil, errors.New("unsupported encrypted PEM")
}

// 解出 PKCS8 密钥
// 加密方式: AES-128-CBC | AES-192-CBC | AES-256-CBC | DES | 3DES
func DecryptPKCS8PrivateKey(data, password []byte) ([]byte, error) {
    var pki encryptedPrivateKeyInfo
    if _, err := asn1.Unmarshal(data, &pki); err != nil {
        return nil, errors.New(err.Error() + " failed to unmarshal private key")
    }

    if !pki.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
        return nil, errors.New("unsupported encrypted PEM: only PBES2 is supported")
    }

    var params pbes2Params
    if _, err := asn1.Unmarshal(pki.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
        return nil, errors.New("pkcs8: invalid PBES2 parameters")
    }

    if !params.KeyDerivationFunc.Algorithm.Equal(oidPKCS5PBKDF2) {
        return nil, errors.New("unsupported encrypted PEM: only PBKDF2 is supported")
    }

    var iv []byte
    if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
        return nil, errors.New("pkcs8: invalid PBES2 iv")
    }

    var kdfParam pbkdf2Params
    if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdfParam); err != nil {
        return nil, errors.New("pkcs8: invalid PBES2 parameters")
    }

    salt := kdfParam.Salt
    iter := kdfParam.IterationCount

    // pbkdf2 hash function
    keyHash := prfByOID(kdfParam.PrfParam.Algorithm)
    if keyHash == nil {
        return nil, errors.New("unsupported PRF")
    }

    var symkey []byte
    var block cipher.Block
    var err error
    switch {
        // AES-128-CBC, AES-192-CBC, AES-256-CBC
        case params.EncryptionScheme.Algorithm.Equal(oidAES128CBC):
            symkey = pbkdf2.Key(password, salt, iter, 16, keyHash)
            block, err = aes.NewCipher(symkey)
        case params.EncryptionScheme.Algorithm.Equal(oidAES192CBC):
            symkey = pbkdf2.Key(password, salt, iter, 24, keyHash)
            block, err = aes.NewCipher(symkey)
        case params.EncryptionScheme.Algorithm.Equal(oidAES256CBC):
            symkey = pbkdf2.Key(password, salt, iter, 32, keyHash)
            block, err = aes.NewCipher(symkey)
        // DES, TripleDES
        case params.EncryptionScheme.Algorithm.Equal(oidDESCBC):
            symkey = pbkdf2.Key(password, salt, iter, 8, keyHash)
            block, err = des.NewCipher(symkey)
        case params.EncryptionScheme.Algorithm.Equal(oidDESEDE3CBC):
            symkey = pbkdf2.Key(password, salt, iter, 24, keyHash)
            block, err = des.NewTripleDESCipher(symkey)
        default:
            return nil, errors.New(fmt.Sprintf("unsupported encrypted PEM: unknown algorithm %v", params.EncryptionScheme.Algorithm))
    }

    if err != nil {
        return nil, err
    }

    data = pki.EncryptedData

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(data, data)

    // 解析加密数据
    blockSize := block.BlockSize()
    dlen := len(data)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("error decrypting PEM: invalid padding")
    }

    last := int(data[dlen-1])
    if dlen < last {
        return nil, x509.IncorrectPasswordError
    }
    if last == 0 || last > blockSize {
        return nil, x509.IncorrectPasswordError
    }

    for _, val := range data[dlen-last:] {
        if int(val) != last {
            return nil, x509.IncorrectPasswordError
        }
    }

    return data[:dlen-last], nil
}

// 加密 PKCS8
func EncryptPKCS8PrivateKey(
    rand io.Reader,
    blockType string,
    data []byte,
    password []byte,
    alg x509.PEMCipher,
    opts ...any,
) (*pem.Block, error) {
    ciph := cipherByKey(alg)
    if ciph == nil {
        return nil, errors.New(fmt.Sprintf("failed to encrypt PEM: unknown algorithm %v", alg))
    }

    var opt any
    if len(opts) > 0 {
        opt = opts[0]
    } else {
        opt = DefaultOpts
    }

    var oidhash string
    var saltSize int
    var iterationCount int

    // 断言类型
    switch opt.(type) {
        case Opts:
            optData := opt.(Opts)

            oidhash = optData.HMACHash
            saltSize = optData.SaltSize
            iterationCount = optData.IterationCount
        case string:
            oidhash = opt.(string)
            saltSize = DefaultOpts.SaltSize
            iterationCount = DefaultOpts.IterationCount
        default:
            oidhash = DefaultOpts.HMACHash
            saltSize = DefaultOpts.SaltSize
            iterationCount = DefaultOpts.IterationCount
    }

    // 签名方式
    oidUseHash := sha1.New
    if selectedHash, ok := oidHashs[oidhash]; ok {
        oidUseHash = selectedHash
    }

    // ObjectIdentifier 方式
    oidUseAsn1 := oidHMACWithSHA1
    if selectedAsn1, ok := oidAsn1s[oidhash]; ok {
        oidUseAsn1 = selectedAsn1
    }

    salt := make([]byte, saltSize)
    if _, err := io.ReadFull(rand, salt); err != nil {
        return nil, errors.New(err.Error() + " failed to generate salt")
    }

    iv := make([]byte, ciph.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, errors.New(err.Error() + " failed to generate IV")
    }

    key := ciph.deriveKey(password, salt, iterationCount, oidUseHash)
    block, err := ciph.cipherFunc(key)
    if err != nil {
        return nil, errors.New(err.Error() + " failed to create cipher")
    }

    enc := cipher.NewCBCEncrypter(block, iv)
    pad := ciph.blockSize - len(data)%ciph.blockSize
    encrypted := make([]byte, len(data), len(data)+pad)

    copy(encrypted, data)
    // See RFC 1423, section 1.1
    for i := 0; i < pad; i++ {
        encrypted = append(encrypted, byte(pad))
    }
    enc.CryptBlocks(encrypted, encrypted)

    // 生成 asn1 数据开始
    kdfParams := pbkdf2Params{
        Salt:           salt,
        IterationCount: iterationCount,
        PrfParam: pkix.AlgorithmIdentifier{
            Algorithm:  oidUseAsn1,
            Parameters: asn1.RawValue{
                Tag: asn1.TagNull,
            },
        },
    }

    marshalledParams, err := asn1.Marshal(kdfParams)
    if err != nil {
        return nil, err
    }

    keyDerivationFunc := pkix.AlgorithmIdentifier{
        Algorithm:  oidPKCS5PBKDF2,
        Parameters: asn1.RawValue{
            FullBytes: marshalledParams,
        },
    }

    marshalledIV, err := asn1.Marshal(iv)
    if err != nil {
        return nil, err
    }

    encryptionScheme := pkix.AlgorithmIdentifier{
        Algorithm:  ciph.identifier,
        Parameters: asn1.RawValue{
            FullBytes: marshalledIV,
        },
    }

    encryptionAlgorithmParams := pbes2Params{
        EncryptionScheme:  encryptionScheme,
        KeyDerivationFunc: keyDerivationFunc,
    }
    marshalledEncryptionAlgorithmParams, err := asn1.Marshal(encryptionAlgorithmParams)
    if err != nil {
        return nil, err
    }

    encryptionAlgorithm := pkix.AlgorithmIdentifier{
        Algorithm:  oidPBES2,
        Parameters: asn1.RawValue{
            FullBytes: marshalledEncryptionAlgorithmParams,
        },
    }

    // 生成 ans1 数据
    pki := encryptedPrivateKeyInfo{
        EncryptionAlgorithm: encryptionAlgorithm,
        EncryptedData:       encrypted,
    }

    b, err := asn1.Marshal(pki)
    if err != nil {
        return nil, errors.New(err.Error() + " error marshaling encrypted key")
    }

    return &pem.Block{
        Type:  blockType,
        Bytes: b,
    }, nil
}
