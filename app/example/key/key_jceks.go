package key

import (
    "fmt"
    "bytes"
    "errors"
    "encoding/pem"
    "encoding/asn1"
    "encoding/binary"

    "github.com/deatil/lakego-filesystem/filesystem"

    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
    cryptobin_jceks "github.com/deatil/go-cryptobin/jceks"
)

func MakedWebJceksBase64() error {
    fs := filesystem.New()

    path := "./runtime/key/jceks/%s"

    jceksFile := fmt.Sprintf(path, "private-key.jceks")
    jceks, _ := fs.Get(jceksFile)

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: []byte(jceks),
    }

    privStr := pem.EncodeToMemory(privateBlock)

    base64File := fmt.Sprintf(path, "jceks.pem")
    fs.Put(base64File, string(privStr))

    fmt.Println("priv =====")
    fmt.Printf("%#v", privStr)
    fmt.Println("")

    return nil
}

type jksConfig struct {
    filename string
    passwd string
    keypass string
    alias string
    typ string
}

func ShowJks() error {
    conf := jksConfig{
        // filename: "trusted-cert",
        filename: "data/newdata/pri-key",
        passwd: "pri-key-store-password",
        keypass: "pri-key-key-password",
        alias: "pri-key-some-alias",
        typ: "private", // private | other
    }

    return ShowJksData(conf)
}

func ShowJksData(conf jksConfig) error {
    fs := filesystem.New()

    filename := conf.filename
    typ := conf.typ

    path := "./runtime/key/jceks/jks/%s"
    // path := "./runtime/key/jceks/jks/newdata/%s"

    jceksFile := fmt.Sprintf(path, filename + ".jks")
    jceksData, _ := fs.Get(jceksFile)

    passwd := conf.passwd
    keypass := conf.keypass
    alias := conf.alias

    ks, err := cryptobin_jceks.LoadJksFromBytes([]byte(jceksData), passwd)
    if err != nil {
        return err
    }

    if typ == "private" {
        key, err := ks.GetPrivateKey(alias, keypass)
        if err != nil {
            fmt.Println("key err =====")
            fmt.Println(err.Error())
        }

        fmt.Println("key =====")
        fmt.Printf("%#v", key)
        fmt.Println("")

        certs, err := ks.GetCertChain(alias)
        if err != nil {
            fmt.Println("certs err =====")
            fmt.Println(err.Error())
        }

        fmt.Println("certs =====")
        fmt.Printf("%#v", certs)
        fmt.Println("")

        certsBytes, err := ks.GetCertChainBytes(alias)
        if err != nil {
            fmt.Println("certsBytes err =====")
            fmt.Println(err.Error())
        }

        fmt.Println("certsBytes =====")
        fmt.Printf("%#v", certsBytes)
        fmt.Println("")

        date, err := ks.GetCreateDate(alias)
        if err != nil {
            fmt.Println("date err =====")
            fmt.Println(err.Error())
        }

        fmt.Println("date =====")
        fmt.Println(date)

        priAliases := ks.ListPrivateKeys()

        fmt.Println("priAliases =====")
        fmt.Printf("%#v", priAliases)
        fmt.Println("")
    } else {
        cert, err := ks.GetCert(alias)
        if err != nil {
            fmt.Println("cert err =====")
            fmt.Println(err.Error())
        }

        fmt.Println("cert =====")
        fmt.Printf("%#v", cert)
        fmt.Println("")

        certBytes, err := ks.GetCertBytes(alias)
        if err != nil {
            fmt.Println("certBytes err =====")
            fmt.Println(err.Error())
        }

        fmt.Println("certBytes =====")
        fmt.Printf("%#v", certBytes)
        fmt.Println("")

        date, err := ks.GetCreateDate(alias)
        if err != nil {
            fmt.Println("date err =====")
            fmt.Println(err.Error())
        }

        fmt.Println("date =====")
        fmt.Println(date)

        certAliases := ks.ListCerts()

        fmt.Println("certAliases =====")
        fmt.Printf("%#v", certAliases)
        fmt.Println("")
    }

    return nil
}

func MakeJksPriKey() error {
    fs := filesystem.New()

    filename := "pri-key"

    passwd := filename + "-store-password"
    keypass := filename + "-key-password"
    alias := filename + "-some-alias"

    path := "./runtime/key/jceks/jks/data/%s"

    certificateFile := fmt.Sprintf(path, "private-key.crt")
    privateKeyFile := fmt.Sprintf(path, "private-key.key")

    certificateData, _ := fs.Get(certificateFile)
    privateKeyData, _ := fs.Get(privateKeyFile)

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }

    certBytes := certificateBlock.Bytes

    privateKey := cryptobin_rsa.NewRsa().
        FromPrivateKey([]byte(privateKeyData)).
        GetPrivateKey()

    certs := make([][]byte, 0)
    certs = append(certs, certBytes)

    en := cryptobin_jceks.NewJksEncode()
    en.AddPrivateKey(alias, privateKey, keypass, certs)

    pfxData, err := en.Marshal(passwd)
    if err != nil {
        return err
    }

    jceksFile := fmt.Sprintf(path, "newdata/"+filename+".jks")
    fs.Put(jceksFile, string(pfxData))

    return nil
}

func MakeJksTrustedCert() error {
    fs := filesystem.New()

    filename := "trusted-cert"

    passwd := filename + "-store-password"
    alias := filename + "-some-alias"

    path := "./runtime/key/jceks/jks/data/%s"

    certificateFile := fmt.Sprintf(path, "trusted-cert.crt")

    certificateData, _ := fs.Get(certificateFile)

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }

    certBytes := certificateBlock.Bytes

    en := cryptobin_jceks.NewJksEncode()
    en.AddTrustedCert(alias, certBytes)

    pfxData, err := en.Marshal(passwd)
    if err != nil {
        return err
    }

    jceksFile := fmt.Sprintf(path, "newdata/"+filename+".jks")
    fs.Put(jceksFile, string(pfxData))

    return nil
}

func ShowJceks() error {
    filename := "trusted-cert"
    typ := "other" // private | secret | other

    return ShowJceksData(filename, typ)
}

func ShowJceksData(filename string, typ string) error {
    fs := filesystem.New()

    path := "./runtime/key/jceks/testdata/%s"
    // path := "./runtime/key/jceks/testdata/newdata/%s"

    jceksFile := fmt.Sprintf(path, filename + ".jceks")
    jceksData, _ := fs.Get(jceksFile)

    passwd := filename + "-store-password"
    keypass := filename + "-key-password"
    alias := filename + "-some-alias"

    ks, err := cryptobin_jceks.LoadFromBytes([]byte(jceksData), passwd)
    if err != nil {
        return err
    }

    if typ == "private" {
        key, certs, err := ks.GetPrivateKeyAndCerts(alias, keypass)
        if err != nil {
            return err
        }

        if key == nil {
            return errors.New("unable to load key")
        }

        fmt.Println("key =====")
        fmt.Printf("%#v", key)
        fmt.Println("")

        fmt.Println("certs =====")
        fmt.Printf("%#v", certs[0])
        fmt.Println("")

        _, certsBytes, err := ks.GetPrivateKeyAndCertsBytes(alias, keypass)
        if err != nil {
            return err
        }

        fmt.Println("certsBytes =====")
        fmt.Printf("%#v", certsBytes)
        fmt.Println("")

        keyAliases := ks.ListPrivateKeys()

        fmt.Println("keyAliases =====")
        fmt.Printf("%#v", keyAliases)
        fmt.Println("")
    } else if typ == "secret" {
        secret, err := ks.GetSecretKey(alias, keypass)
        if err != nil {
            return err
        }

        fmt.Println("secret =====")
        fmt.Println(string(secret))

        secretAliases := ks.ListSecretKeys()

        fmt.Println("secretAliases =====")
        fmt.Printf("%#v", secretAliases)
        fmt.Println("")
    } else {
        cert, err := ks.GetCert(alias)
        if err != nil {
            return err
        }

        if cert == nil {
            return errors.New("unable to load cert")
        }

        fmt.Println("cert =====")
        fmt.Printf("%#v", cert)
        fmt.Println("")

        certBytes, err := ks.GetCertBytes(alias)
        if err != nil {
            return err
        }

        fmt.Println("certBytes =====")
        fmt.Printf("%#v", certBytes)
        fmt.Println("")

        certAliases := ks.ListCerts()

        fmt.Println("certAliases =====")
        fmt.Printf("%#v", certAliases)
        fmt.Println("")
    }

    // pkcs12File := fmt.Sprintf(path, "pkcs12.p12")
    // fs.Put(pkcs12File, string(pfxData))

    return nil
}

func MakeJceksPriKey() error {
    fs := filesystem.New()

    filename := "pri-key"

    passwd := filename + "-store-password"
    keypass := filename + "-key-password"
    alias := filename + "-some-alias"

    path := "./runtime/key/jceks/testdata/%s"

    certificateFile := fmt.Sprintf(path, "private-key.crt")
    privateKeyFile := fmt.Sprintf(path, "private-key.key")

    certificateData, _ := fs.Get(certificateFile)
    privateKeyData, _ := fs.Get(privateKeyFile)

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }

    certBytes := certificateBlock.Bytes

    privateKey := cryptobin_rsa.NewRsa().
        FromPrivateKey([]byte(privateKeyData)).
        GetPrivateKey()

    certs := make([][]byte, 0)
    certs = append(certs, certBytes)

    en := cryptobin_jceks.NewJceksEncode()
    en.AddPrivateKey(alias, privateKey, keypass, certs)

    pfxData, err := en.Marshal(passwd)
    if err != nil {
        return err
    }

    jceksFile := fmt.Sprintf(path, "newdata/"+filename+".jceks")
    fs.Put(jceksFile, string(pfxData))

    return nil
}

func MakeJceksTrustedCert() error {
    fs := filesystem.New()

    filename := "trusted-cert"

    passwd := filename + "-store-password"
    alias := filename + "-some-alias"

    path := "./runtime/key/jceks/testdata/%s"

    certificateFile := fmt.Sprintf(path, "trusted-cert.crt")

    certificateData, _ := fs.Get(certificateFile)

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }

    certBytes := certificateBlock.Bytes

    en := cryptobin_jceks.NewJceksEncode()
    en.AddTrustedCert(alias, certBytes)

    pfxData, err := en.Marshal(passwd)
    if err != nil {
        return err
    }

    jceksFile := fmt.Sprintf(path, "newdata/"+filename+".jceks")
    fs.Put(jceksFile, string(pfxData))

    return nil
}

func MakeJceksSecretKey() error {
    fs := filesystem.New()

    filename := "secret-key"

    passwd := filename + "-store-password"
    keypass := filename + "-key-password"
    alias := filename + "-some-alias"

    path := "./runtime/key/jceks/testdata/%s"

    secretKey := "secretKey-ertw452345234sgsd"

    en := cryptobin_jceks.NewJceksEncode()
    en.AddSecretKey(alias, []byte(secretKey), keypass)

    pfxData, err := en.Marshal(passwd)
    if err != nil {
        return err
    }

    jceksFile := fmt.Sprintf(path, "newdata/"+filename+".jceks")
    fs.Put(jceksFile, string(pfxData))

    return nil
}

// 设置
type bcryptParams struct {
    Salt   string
    Rounds uint32
}

func ASN1Test() error {
    // 存字节
    salt := []byte("asdew23r")
    rounds := 1000
    saltlen := len(salt)

    buf := new(bytes.Buffer)
    binary.Write(buf, binary.BigEndian, uint32(saltlen))
    binary.Write(buf, binary.BigEndian, salt)
    binary.Write(buf, binary.BigEndian, uint32(rounds))
    params := buf.String()

    fmt.Println("buf =====")
    fmt.Println(params)

    buf2 := bytes.NewReader([]byte(params))

    var newSaltlen uint32
    if err := binary.Read(buf2, binary.BigEndian, &newSaltlen); err != nil {
        fmt.Println("newSaltlen err =====")
        fmt.Println(err.Error())
    }

    newSalt := make([]byte, newSaltlen)
    if err := binary.Read(buf2, binary.BigEndian, &newSalt); err != nil {
        fmt.Println("newSalt err =====")
        fmt.Println(err.Error())
    }

    var newRounds uint32
    if err := binary.Read(buf2, binary.BigEndian, &newRounds); err != nil {
        fmt.Println("newRounds err =====")
        fmt.Println(err.Error())
    }

    fmt.Println("newSaltlen =====")
    fmt.Println(newSaltlen)
    fmt.Println("newSalt =====")
    fmt.Println(string(newSalt))
    fmt.Println("newRounds =====")
    fmt.Println(newRounds)

    // 解析参数
    var param bcryptParams
    _, err := asn1.Unmarshal([]byte(params), &param)
    if err != nil {
        fmt.Println("err =====")
        fmt.Println(err.Error())
    }

    fmt.Println("param =====")
    fmt.Println(param)

    return nil
}

