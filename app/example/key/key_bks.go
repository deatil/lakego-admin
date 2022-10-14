package key

import (
    "fmt"
    "errors"
    "encoding/pem"

    "github.com/deatil/lakego-filesystem/filesystem"

    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
    cryptobin_jceks "github.com/deatil/go-cryptobin/jceks"
)

type bksConfig struct {
    filename string
    passwd string
    typ string

    sealedType string
    sealedpasswd string
}

func ShowBks() error {
    conf := bksConfig{
        // custom_entry_passwords.bksv1 | christmas.bksv2 | uber
        filename: "testdata/bks/empty.bksv1",
        passwd: "", // store_password | 12345678
        typ: "private", // list | private | other

        sealedType: "sealed_private_key",
        sealedpasswd: "",
    }

    return ShowBksData(conf)
}

func ShowBksData(conf bksConfig) error {
    fs := filesystem.New()

    filename := conf.filename
    typ := conf.typ

    path := "./runtime/key/bks/%s"
    // path := "./runtime/key/jceks/jks/newdata/%s"

    bksFile := fmt.Sprintf(path, filename)
    bksData, _ := fs.Get(bksFile)

    passwd := conf.passwd

    // LoadUber | LoadBksFromBytes
    ks, err := cryptobin_jceks.LoadUber([]byte(bksData), passwd)
    if err != nil {
        return err
    }

    // [cert] cert
    // [secretKey] stored_value
    // [sealedKeys] sealed_private_key | sealed_public_key | sealed_secret_key
    // [key] plain_key
    if typ == "private" {
        keyType, err := ks.GetKeyType("plain_key")

        fmt.Println("===== keyType =====")
        fmt.Printf("%#v", keyType)
        fmt.Printf("\n err: %#v", err)
        fmt.Println("")

        date, err := ks.GetCreateDate("plain_key")
        certChain, err := ks.GetCertChain("plain_key")
        // _, _, secret, err := ks.GetKey("plain_key")
        secret, err := ks.GetKeySecret("plain_key")

        fmt.Println("===== key =====")
        fmt.Printf("secret: %#v", secret)
        fmt.Println("")
        fmt.Printf("certChain: %#v", certChain)
        fmt.Println("")
        fmt.Println("date: " + date.String())
        fmt.Printf("err: %#v", err)
        fmt.Println("")

        date, err = ks.GetCreateDate("cert")
        certType, err := ks.GetCertType("cert")
        certChain, err = ks.GetCertChain("cert")
        cert, err := ks.GetCert("cert")

        fmt.Println("===== cert =====")
        fmt.Printf("cert: %#v", cert)
        fmt.Println("")
        fmt.Println("certType: " + certType)
        fmt.Printf("certChain: %#v", certChain)
        fmt.Println("")
        fmt.Println("date: " + date.String())
        fmt.Printf("err: %#v", err)
        fmt.Println("")

        date, err = ks.GetCreateDate("stored_value")
        certChain, err = ks.GetCertChain("stored_value")
        secret, err = ks.GetSecretKey("stored_value")

        fmt.Println("===== secret =====")
        fmt.Printf("secret: %#v", secret)
        fmt.Println("")
        fmt.Printf("certChain: %#v", certChain)
        fmt.Println("")
        fmt.Println("date: " + date.String())
        fmt.Printf("err: %#v", err)
        fmt.Println("")

        sealedType := conf.sealedType
        sealedKeyTypeString, err := ks.GetSealedKeyType(sealedType, conf.sealedpasswd)

        fmt.Println("===== sealedKeyTypeString =====")
        fmt.Printf("%#v", sealedKeyTypeString)
        fmt.Printf("\n err: %#v", err)
        fmt.Println("")

        date, err = ks.GetCreateDate(sealedType)
        certChain, err = ks.GetCertChain(sealedType)
        // privateKey, publicKey, secret, err := ks.GetSealedKey(sealedType, conf.sealedpasswd)
        privateKey, err := ks.GetKeyPrivateWithPassword(sealedType, conf.sealedpasswd)
        publicKey, err := ks.GetKeyPublicWithPassword(sealedType, conf.sealedpasswd)
        secret, err = ks.GetKeySecretWithPassword(sealedType, conf.sealedpasswd)

        fmt.Println("===== sealedKeys =====")
        fmt.Printf("privateKey: %#v", privateKey)
        fmt.Println("")
        fmt.Printf("publicKey: %#v", publicKey)
        fmt.Println("")
        fmt.Printf("secret: %#v", secret)
        fmt.Println("")
        fmt.Printf("certChain: %#v", certChain)
        fmt.Println("")
        fmt.Println("date: " + date.String())
        fmt.Printf("err: %#v", err)
        fmt.Println("")

        fmt.Println("===== data =====")
        fmt.Printf("Version: %d", ks.Version())
        fmt.Println("")
        fmt.Println("StoreType: " + ks.StoreType())

    } else if typ == "list" {
        certsAliases := ks.ListCerts()

        fmt.Println("===== certsAliases =====")
        fmt.Printf("%#v", certsAliases)
        fmt.Println("")

        secretKeysAliases := ks.ListSecretKeys()

        fmt.Println("===== secretKeysAliases =====")
        fmt.Printf("%#v", secretKeysAliases)
        fmt.Println("")

        sealedKeysAliases := ks.ListSealedKeys()

        fmt.Println("===== sealedKeysAliases =====")
        fmt.Printf("%#v", sealedKeysAliases)
        fmt.Println("")

        keyAliases := ks.ListKeys()

        fmt.Println("===== keyAliases =====")
        fmt.Printf("%#v", keyAliases)
        fmt.Println("")
    } else {

    }

    return nil
}

func MakeBksChristmasStore() error {
    fs := filesystem.New()
    ks := cryptobin_jceks.NewBksEncode()

    password := "12345678"
    ver := 2

    path := "./runtime/key/bks/testdata/%s"

    certificateFile := fmt.Sprintf(path, "private-key.crt")
    certificateData, _ := fs.Get(certificateFile)

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }
    certBytes := certificateBlock.Bytes

    certs := make([][]byte, 0)
    certs = append(certs, certBytes)

    privateKeyFile := fmt.Sprintf(path, "private-key.key")
    privateKeyData, _ := fs.Get(privateKeyFile)
    privateKey := cryptobin_rsa.NewRsa().
        FromPrivateKey([]byte(privateKeyData)).
        GetPrivateKey()

    publicKeyFile := fmt.Sprintf(path, "private-key.pub")
    publicKeyData, _ := fs.Get(publicKeyFile)
    publicKey := cryptobin_rsa.NewRsa().
        FromPublicKey([]byte(publicKeyData)).
        GetPublicKey()

    secretKey := []byte("sealed_secret_key-data")
    storedValue := []byte("stored_value-data")
    plainKey := []byte("plain_key-data")

    ks.AddCert("cert", certBytes, nil);
    ks.AddKeyPrivateWithPassword("sealed_private_key", privateKey, password, certs);
    ks.AddKeyPublicWithPassword("sealed_public_key", publicKey, password, nil);
    ks.AddKeySecretWithPassword("sealed_secret_key", secretKey, password, "AES", nil);
    ks.AddSecret("stored_value", storedValue, nil);
    ks.AddKeySecret("plain_key", plainKey, "AES", nil);

    opts := cryptobin_jceks.BKSOpts{
        Version:        1,
        SaltSize:       20,
        IterationCount: 10000,
    }
    ksFile := fmt.Sprintf(path, "bks/christmas.bksv1")
    if ver == 2 {
        opts = cryptobin_jceks.BKSOpts{
            Version:        2,
            SaltSize:       20,
            IterationCount: 10000,
        }
        ksFile = fmt.Sprintf(path, "bks/christmas.bksv2")
    }

    pfxData, err := ks.Marshal(password, opts)
    if err != nil {
        return err
    }

    fs.Put(ksFile, string(pfxData))

    return nil
}

func MakeBksCustomEntryPasswordsStore() error {
    fs := filesystem.New()
    ks := cryptobin_jceks.NewBksEncode()

    password := "store_password"
    ver := 2

    path := "./runtime/key/bks/testdata/%s"

    certificateFile := fmt.Sprintf(path, "private-key.crt")
    certificateData, _ := fs.Get(certificateFile)

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }
    certBytes := certificateBlock.Bytes

    certs := make([][]byte, 0)
    certs = append(certs, certBytes)

    privateKeyFile := fmt.Sprintf(path, "private-key.key")
    privateKeyData, _ := fs.Get(privateKeyFile)
    privateKey := cryptobin_rsa.NewRsa().
        FromPrivateKey([]byte(privateKeyData)).
        GetPrivateKey()

    publicKeyFile := fmt.Sprintf(path, "private-key.pub")
    publicKeyData, _ := fs.Get(publicKeyFile)
    publicKey := cryptobin_rsa.NewRsa().
        FromPublicKey([]byte(publicKeyData)).
        GetPublicKey()

    secretKey := []byte("sealed_secret_key-data")

    ks.AddKeyPrivateWithPassword("sealed_private_key", privateKey, "private_password", certs);
    ks.AddKeyPublicWithPassword("sealed_public_key", publicKey, "public_password", certs);
    ks.AddKeySecretWithPassword("sealed_secret_key", secretKey, "secret_password", "AES", certs);

    opts := cryptobin_jceks.BKSOpts{
        Version:        1,
        SaltSize:       20,
        IterationCount: 10000,
    }
    ksFile := fmt.Sprintf(path, "bks/custom_entry_passwords.bksv1")

    if ver == 2 {
        opts = cryptobin_jceks.BKSOpts{
            Version:        2,
            SaltSize:       20,
            IterationCount: 10000,
        }
        ksFile = fmt.Sprintf(path, "bks/custom_entry_passwords.bksv2")
    }

    pfxData, err := ks.Marshal(password, opts)
    if err != nil {
        return err
    }

    fs.Put(ksFile, string(pfxData))

    return nil
}

func MakeBksEmptyStore() error {
    fs := filesystem.New()
    ks := cryptobin_jceks.NewBksEncode()

    password := ""
    ver := 1

    path := "./runtime/key/bks/testdata/%s"

    opts := cryptobin_jceks.BKSOpts{
        Version:        1,
        SaltSize:       20,
        IterationCount: 10000,
    }
    ksFile := fmt.Sprintf(path, "bks/empty.bksv1")

    if ver == 2 {
        opts = cryptobin_jceks.BKSOpts{
            Version:        2,
            SaltSize:       20,
            IterationCount: 10000,
        }
        ksFile = fmt.Sprintf(path, "bks/empty.bksv2")
    }

    pfxData, err := ks.Marshal(password, opts)
    if err != nil {
        return err
    }

    fs.Put(ksFile, string(pfxData))

    return nil
}

func MakeUberChristmasStore() error {
    fs := filesystem.New()
    ks := cryptobin_jceks.NewUberEncode()

    password := "12345678"

    path := "./runtime/key/bks/testdata/%s"

    certificateFile := fmt.Sprintf(path, "private-key.crt")
    certificateData, _ := fs.Get(certificateFile)

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }
    certBytes := certificateBlock.Bytes

    certs := make([][]byte, 0)
    certs = append(certs, certBytes)

    privateKeyFile := fmt.Sprintf(path, "private-key.key")
    privateKeyData, _ := fs.Get(privateKeyFile)
    privateKey := cryptobin_rsa.NewRsa().
        FromPrivateKey([]byte(privateKeyData)).
        GetPrivateKey()

    publicKeyFile := fmt.Sprintf(path, "private-key.pub")
    publicKeyData, _ := fs.Get(publicKeyFile)
    publicKey := cryptobin_rsa.NewRsa().
        FromPublicKey([]byte(publicKeyData)).
        GetPublicKey()

    secretKey := []byte("sealed_secret_key-data")
    storedValue := []byte("stored_value-data")
    plainKey := []byte("plain_key-data")

    ks.AddCert("cert", certBytes, nil);
    ks.AddKeyPrivateWithPassword("sealed_private_key", privateKey, password, certs);
    ks.AddKeyPublicWithPassword("sealed_public_key", publicKey, password, nil);
    ks.AddKeySecretWithPassword("sealed_secret_key", secretKey, password, "AES", nil);
    ks.AddSecret("stored_value", storedValue, nil);
    ks.AddKeySecret("plain_key", plainKey, "AES", nil);

    opts := cryptobin_jceks.UBEROpts{
        SaltSize:       20,
        IterationCount: 10000,
    }
    ksFile := fmt.Sprintf(path, "uber/christmas.uber")

    pfxData, err := ks.Marshal(password, opts)
    if err != nil {
        return err
    }

    fs.Put(ksFile, string(pfxData))

    return nil
}

func MakeUberCustomEntryPasswordsStore() error {
    fs := filesystem.New()
    ks := cryptobin_jceks.NewUberEncode()

    password := "store_password"

    path := "./runtime/key/bks/testdata/%s"

    certificateFile := fmt.Sprintf(path, "private-key.crt")
    certificateData, _ := fs.Get(certificateFile)

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }
    certBytes := certificateBlock.Bytes

    certs := make([][]byte, 0)
    certs = append(certs, certBytes)

    privateKeyFile := fmt.Sprintf(path, "private-key.key")
    privateKeyData, _ := fs.Get(privateKeyFile)
    privateKey := cryptobin_rsa.NewRsa().
        FromPrivateKey([]byte(privateKeyData)).
        GetPrivateKey()

    publicKeyFile := fmt.Sprintf(path, "private-key.pub")
    publicKeyData, _ := fs.Get(publicKeyFile)
    publicKey := cryptobin_rsa.NewRsa().
        FromPublicKey([]byte(publicKeyData)).
        GetPublicKey()

    secretKey := []byte("sealed_secret_key-data")

    ks.AddKeyPrivateWithPassword("sealed_private_key", privateKey, "private_password", certs);
    ks.AddKeyPublicWithPassword("sealed_public_key", publicKey, "public_password", certs);
    ks.AddKeySecretWithPassword("sealed_secret_key", secretKey, "secret_password", "AES", certs);

    opts := cryptobin_jceks.UBEROpts{
        SaltSize:       20,
        IterationCount: 10000,
    }
    ksFile := fmt.Sprintf(path, "uber/custom_entry_passwords.uber")

    pfxData, err := ks.Marshal(password, opts)
    if err != nil {
        return err
    }

    fs.Put(ksFile, string(pfxData))

    return nil
}

func MakeUberEmptyStore() error {
    fs := filesystem.New()
    ks := cryptobin_jceks.NewUberEncode()

    password := ""

    path := "./runtime/key/bks/testdata/%s"

    opts := cryptobin_jceks.UBEROpts{
        SaltSize:       20,
        IterationCount: 10000,
    }
    ksFile := fmt.Sprintf(path, "uber/empty.uber")

    pfxData, err := ks.Marshal(password, opts)
    if err != nil {
        return err
    }

    fs.Put(ksFile, string(pfxData))

    return nil
}
