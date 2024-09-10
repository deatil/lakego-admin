package passhash9

import (
    "io"
    "fmt"
    "bytes"
    "strings"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/cipher"
    "encoding/binary"
    "encoding/base64"

    "golang.org/x/crypto/blowfish"

    "github.com/deatil/go-cryptobin/kdf/pbkdf2"
)

const MAGIC_PREFIX = "$9$"

const WORKFACTOR_BYTES = 2
const ALGID_BYTES = 1
const SALT_BYTES  = 12                 // 96 bits of salt
const PASSHASH9_PBKDF_OUTPUT_LEN = 24  // 192 bits output

const WORK_FACTOR_SCALE = 10000

func GenerateHash(
    rand       io.Reader,
    pass       string,
    workFactor uint16,
    algId      int,
) string {
    if !(workFactor > 0 && workFactor < 512) {
        panic("Passhash9: Invalid Passhash9 work factor")
    }

    prf := GetPbkdfPRF(algId)
    if prf == nil {
        panic(fmt.Sprintf("Passhash9: Algorithm id %d is not defined", algId))
    }

    salt := make([]byte, SALT_BYTES)
    if _, err := io.ReadFull(rand, salt); err != nil {
        panic("Passhash9: rand Passhash9 salt fail")
    }

    iterations := WORK_FACTOR_SCALE * int(workFactor)

    blob := make([]byte, 0)
    blob = append(blob, byte(algId))

    workFactorBytes := make([]byte, 2)
    putu16(workFactorBytes, workFactor)

    blob = append(blob, workFactorBytes...)
    blob = append(blob, salt...)

    deriveKey := pbkdf2.Key([]byte(pass), salt, iterations, PASSHASH9_PBKDF_OUTPUT_LEN, prf)
    blob = append(blob, deriveKey...)

    data := base64.StdEncoding.EncodeToString(blob)

    return MAGIC_PREFIX + data
}

func CompareHash(pass string, hash string) bool {
    BINARY_LENGTH := ALGID_BYTES + WORKFACTOR_BYTES + PASSHASH9_PBKDF_OUTPUT_LEN + SALT_BYTES

    BASE64_LENGTH := len(MAGIC_PREFIX) + (BINARY_LENGTH * 8) / 6

    if len(hash) != BASE64_LENGTH {
        return false
    }

    if !strings.HasPrefix(hash, MAGIC_PREFIX) {
        return false
    }

    bin, _ := base64.StdEncoding.DecodeString(hash[len(MAGIC_PREFIX):])

    if len(bin) != BINARY_LENGTH {
        return false
    }

    algId := int(bin[0])

    workFactor := int(getu16(bin[1:]))

    if workFactor == 0 {
        return false
    }

    if workFactor > 512 {
        panic(fmt.Sprintf("Passhash9: Requested passhash9 work factor %d is too large", workFactor))
    }

    iterations := WORK_FACTOR_SCALE * workFactor

    prf := GetPbkdfPRF(algId)
    if prf == nil {
        return false
    }

    salt := bin[ALGID_BYTES + WORKFACTOR_BYTES:ALGID_BYTES + WORKFACTOR_BYTES + SALT_BYTES]
    cmp := pbkdf2.Key([]byte(pass), salt, iterations, PASSHASH9_PBKDF_OUTPUT_LEN, prf)

    hashbytes := bin[ALGID_BYTES + WORKFACTOR_BYTES + SALT_BYTES:]

    return bytes.Equal(cmp, hashbytes)
}

func GetPbkdfPRF(algId int) pbkdf2.PRF {
    switch algId {
        case 0:
            // HMAC(SHA-1)
            return pbkdf2.HmacPRF{
                Hash: sha1.New,
            }
        case 1:
            // HMAC(SHA-256)
            return pbkdf2.HmacPRF{
                Hash: sha256.New,
            }
        case 2:
            // CMAC(Blowfish)
            return pbkdf2.CmacPRF{
                Cipher: func(key []byte) (cipher.Block, error) {
                    return blowfish.NewCipher(key)
                },
            }
        case 3:
            // HMAC(SHA-384)
            return pbkdf2.HmacPRF{
                Hash: sha512.New384,
            }
        case 4:
            // HMAC(SHA-512)
            return pbkdf2.HmacPRF{
                Hash: sha512.New,
            }
    }

    return nil
}

func IsAlgSupported(algId int) bool {
   if GetPbkdfPRF(algId) != nil {
      return true
   }

   return false
}

func getu16(ptr []byte) uint16 {
    return binary.BigEndian.Uint16(ptr)
}

func putu16(ptr []byte, a uint16) {
    binary.BigEndian.PutUint16(ptr, a)
}
