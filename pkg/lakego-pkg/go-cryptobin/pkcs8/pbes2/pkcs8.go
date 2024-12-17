package pbes2

import (
    "io"
    "fmt"
    "errors"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
)

var (
    // key derivation functions
    oidRSADSI  = asn1.ObjectIdentifier{1, 2, 840, 113549}
    oidPBES2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
    oidSMPBES2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 4, 1, 5, 2}
)

// 配置
type Opts struct {
    Cipher  Cipher
    KDFOpts KDFOpts
}

// 默认配置 PBKDF2
var DefaultPBKDF2Opts = PBKDF2Opts{
    SaltSize:       16,
    IterationCount: 10000,
}

// 默认配置 GmSM PBKDF2
var DefaultSMPBKDF2Opts = SMPBKDF2Opts{
    SaltSize:       16,
    IterationCount: 10000,
    HMACHash:       DefaultSMHash,
}

// 默认配置 Scrypt
var DefaultScryptOpts = ScryptOpts{
    SaltSize:                 16,
    CostParameter:            1 << 2,
    BlockSize:                8,
    ParallelizationParameter: 1,
}

// 默认配置
var DefaultOpts = Opts{
    Cipher:  AES256CBC,
    KDFOpts: DefaultPBKDF2Opts,
}

// 默认 GmSM 配置
var DefaultSMOpts = Opts{
    Cipher:  SM4CBC,
    KDFOpts: DefaultSMPBKDF2Opts,
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
    rand      io.Reader,
    blockType string,
    data      []byte,
    password  []byte,
    opts      ...Opts,
) (*pem.Block, error) {
    opt := &DefaultOpts
    if len(opts) > 0 {
        opt = &opts[0]
    }

    encrypted, encryptionAlgorithm, err := PBES2Encrypt(rand, data, password, opt)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs8: " + err.Error())
    }

    // 生成 ans1 数据
    pki := encryptedPrivateKeyInfo{
        EncryptionAlgorithm: encryptionAlgorithm,
        EncryptedData:       encrypted,
    }

    b, err := asn1.Marshal(pki)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs8: error marshaling encrypted key: " + err.Error())
    }

    return &pem.Block{
        Type:  blockType,
        Bytes: b,
    }, nil
}

// 解密 PKCS8
func DecryptPKCS8PrivateKey(data, password []byte) ([]byte, error) {
    var pki encryptedPrivateKeyInfo
    if _, err := asn1.Unmarshal(data, &pki); err != nil {
        return nil, errors.New("go-cryptobin/pkcs8: failed to unmarshal private key: " + err.Error())
    }

    algo := pki.EncryptionAlgorithm
    encryptedKey := pki.EncryptedData

    decryptedKey, err := PBES2Decrypt(encryptedKey, algo, password)
    if err != nil {
        return nil, errors.New("go-cryptobin/pkcs8: " + err.Error())
    }

    return decryptedKey, nil
}

// 解出 PEM 块
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
    if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
        return pkcs1.DecryptPEMBlock(block, password)
    }

    // PKCS#8 header defined in RFC7468 section 11
    if block.Type == "ENCRYPTED PRIVATE KEY" {
        return DecryptPKCS8PrivateKey(block.Bytes, password)
    }

    return nil, errors.New("go-cryptobin/pkcs8: unsupported encrypted PEM")
}

// PBES2 加密
func PBES2Encrypt(rand io.Reader, data []byte, password []byte, opt *Opts) (encrypted []byte, algo pkix.AlgorithmIdentifier, err error) {
    cipher := opt.Cipher
    if cipher == nil {
        err = errors.New("unknown opts cipher")
        return
    }

    kdfOpts := opt.KDFOpts
    if kdfOpts == nil {
        err = errors.New("unknown opts kdfOpts")
        return
    }

    salt := make([]byte, kdfOpts.GetSaltSize())
    if _, saltErr := io.ReadFull(rand, salt); saltErr != nil {
        err = errors.New("failed to generate salt: " + err.Error())
        return
    }

    if cipher.HasKeyLength() {
        kdfOpts = kdfOpts.WithHasKeyLength(true)
    }

    key, kdfParams, err := kdfOpts.DeriveKey(password, salt, cipher.KeySize())
    if err != nil {
        return
    }

    encrypted, encryptedParams, err := cipher.Encrypt(rand, key, data)
    if err != nil {
        return
    }

    // 生成 asn1 数据开始
    marshalledParams, err := asn1.Marshal(kdfParams)
    if err != nil {
        return
    }

    keyDerivationFunc := pkix.AlgorithmIdentifier{
        Algorithm:  kdfOpts.OID(),
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
        return
    }

    encryptionAlgorithm := pkix.AlgorithmIdentifier{
        Algorithm:  kdfOpts.PBESOID(),
        Parameters: asn1.RawValue{
            FullBytes: marshalledEncryptionAlgorithmParams,
        },
    }

    return encrypted, encryptionAlgorithm, nil
}

// PBES2 解密
func PBES2Decrypt(data []byte, algo pkix.AlgorithmIdentifier, password []byte) ([]byte, error) {
    if !CheckPBES2(algo.Algorithm) {
        return nil, fmt.Errorf("unsupported PBES (OID: %s)", algo.Algorithm)
    }

    var params pbes2Params
    if _, err := asn1.Unmarshal(algo.Parameters.FullBytes, &params); err != nil {
        return nil, errors.New("invalid PBES2 parameters")
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

    // 生成密钥
    symkey, err := kdfParam.DeriveKey(password, keySize)
    if err != nil {
        return nil, err
    }

    decrypted, err := cipher.Decrypt(symkey, cipherParams, data)
    if err != nil {
        return nil, err
    }

    return decrypted, nil
}

// return true if has pbes2, else return false
func CheckPBES2(oid asn1.ObjectIdentifier) bool {
    for _, kdf := range kdfs {
        if kdf().PBESOID().Equal(oid) {
            return true
        }
    }

    return false
}

// 是否是 PBES2 加密
func IsPBES2(algo asn1.ObjectIdentifier) bool {
    if algo.Equal(oidPBES2) {
        return true
    }

    return false
}

// 是否是 GmSM PBES2 加密
func IsSMPBES2(algo asn1.ObjectIdentifier) bool {
    if algo.Equal(oidSMPBES2) {
        return true
    }

    return false
}

func parseKeyDerivationFunc(keyDerivationFunc pkix.AlgorithmIdentifier) (KDFParameters, error) {
    oid := keyDerivationFunc.Algorithm.String()

    params, ok := kdfs[oid]
    if !ok {
        return nil, fmt.Errorf("unsupported KDF (OID: %s)", oid)
    }

    newParams := params()

    _, err := asn1.Unmarshal(keyDerivationFunc.Parameters.FullBytes, newParams)
    if err != nil {
        return nil, errors.New("invalid KDF parameters")
    }

    return newParams, nil
}

func parseEncryptionScheme(encryptionScheme pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    newCipher, err := GetCipher(encryptionScheme)
    if err != nil {
        oid := encryptionScheme.Algorithm.String()

        return nil, nil, fmt.Errorf("unsupported cipher (OID: %s)", oid)
    }

    params := encryptionScheme.Parameters.FullBytes

    return newCipher, params, nil
}
