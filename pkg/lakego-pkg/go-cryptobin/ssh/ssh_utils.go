package ssh

import (
    "fmt"
)

func ParseCipher(cipherName string) (Cipher, error) {
    cipher, ok := ciphers[cipherName]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported cipher (%s)", cipherName)
    }

    newCipher := cipher()

    return newCipher, nil
}

func ParsePbkdf(kdfName string) (KDFParameters, error) {
    kdf, ok := kdfs[kdfName]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported kdf (%s)", kdfName)
    }

    newKdf := kdf()

    return newKdf, nil
}

func ParseKeytype(keytype string) (Key, error) {
    keyType, ok := keys[keytype]
    if !ok {
        return nil, fmt.Errorf("ssh: unsupported key type %s", keytype)
    }

    newKeytype := keyType()

    return newKeytype, nil
}
