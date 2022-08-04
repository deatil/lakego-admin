package pkcs8

import (
    "io"
    "fmt"
    "errors"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/pem"
)

var (
    // key derivation functions
    oidRSADSI = asn1.ObjectIdentifier{1, 2, 840, 113549}
    oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
)

// KDF 设置接口
type KDFOpts interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 生成密钥
    DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error)

    // 随机数大小
    GetSaltSize() int
}

// 数据接口
type KDFParameters interface {
    // 生成密钥
    DeriveKey(password []byte, size int) (key []byte, err error)
}

// 加密接口
type Cipher interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 值大小
    KeySize() int

    // 加密, 返回: [加密后数据, 参数, error]
    Encrypt(key, plaintext []byte) ([]byte, []byte, error)

    // 解密
    Decrypt(key, params, ciphertext []byte) ([]byte, error)
}

var kdfs = make(map[string]KDFParameters)

// 添加 kdf 方式
func AddKDF(oid asn1.ObjectIdentifier, params KDFParameters) {
    kdfs[oid.String()] = params
}

var ciphers = make(map[string]Cipher)

// 添加加密
func AddCipher(oid asn1.ObjectIdentifier, cipher Cipher) {
    ciphers[oid.String()] = cipher
}

// 配置
type Opts struct {
    Cipher  Cipher
    KDFOpts KDFOpts
}

// 默认配置
var DefaultOpts = Opts{
    Cipher:  AES256CBC,
    KDFOpts: PBKDF2Opts{
        SaltSize:       16,
        IterationCount: 10000,
        HMACHash:       SHA256,
    },
}

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

// 加密 PKCS8
func EncryptPKCS8PrivateKey(
    rand io.Reader,
    blockType string,
    data []byte,
    password []byte,
    opts ...Opts,
) (*pem.Block, error) {
    opt := &DefaultOpts
    if len(opts) > 0 {
        opt = &opts[0]
    }

    cipher := opt.Cipher
    if cipher == nil {
        return nil, errors.New("failed to encrypt PEM: unknown algorithm")
    }

    salt := make([]byte, opt.KDFOpts.GetSaltSize())
    if _, err := io.ReadFull(rand, salt); err != nil {
        return nil, errors.New(err.Error() + " failed to generate salt")
    }

    key, kdfParams, err := opt.KDFOpts.DeriveKey(password, salt, cipher.KeySize())
    if err != nil {
        return nil, err
    }

    encrypted, encryptedParams, err := cipher.Encrypt(key, data)
    if err != nil {
        return nil, err
    }

    // 生成 asn1 数据开始
    marshalledParams, err := asn1.Marshal(kdfParams)
    if err != nil {
        return nil, err
    }

    keyDerivationFunc := pkix.AlgorithmIdentifier{
        Algorithm:  opt.KDFOpts.OID(),
        Parameters: asn1.RawValue{
            FullBytes: marshalledParams,
        },
    }

    encryptionScheme := pkix.AlgorithmIdentifier{
        Algorithm:  cipher.OID(),
        Parameters: asn1.RawValue{
            FullBytes: encryptedParams,
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

    cipher, cipherParams, err := parseEncryptionScheme(params.EncryptionScheme)
    if err != nil {
        return nil, err
    }

    kdfParam, err := parseKeyDerivationFunc(params.KeyDerivationFunc)
    if err != nil {
        return nil, err
    }

    keySize := cipher.KeySize()

    // AES-128-CBC, AES-192-CBC, AES-256-CBC
    // DES, TripleDES
    symkey, err := kdfParam.DeriveKey(password, keySize)
    if err != nil {
        return nil, err
    }

    data = pki.EncryptedData

    decryptedKey, err := cipher.Decrypt(symkey, cipherParams, data)
    if err != nil {
        return nil, err
    }

    return decryptedKey, nil
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

func parseKeyDerivationFunc(keyDerivationFunc pkix.AlgorithmIdentifier) (KDFParameters, error) {
    oid := keyDerivationFunc.Algorithm.String()
    params, ok := kdfs[oid]
    if !ok {
        return nil, fmt.Errorf("pkcs8: unsupported KDF (OID: %s)", oid)
    }

    _, err := asn1.Unmarshal(keyDerivationFunc.Parameters.FullBytes, params)
    if err != nil {
        return nil, errors.New("pkcs8: invalid KDF parameters")
    }

    return params, nil
}

func parseEncryptionScheme(encryptionScheme pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    oid := encryptionScheme.Algorithm.String()
    cipher, ok := ciphers[oid]
    if !ok {
        return nil, nil, fmt.Errorf("pkcs8: unsupported cipher (OID: %s)", oid)
    }

    params := encryptionScheme.Parameters.FullBytes

    return cipher, params, nil
}
