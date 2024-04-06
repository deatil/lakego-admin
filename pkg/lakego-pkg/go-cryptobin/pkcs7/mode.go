package pkcs7

import (
    "encoding/asn1"
)

// 模式
// Mode list
type Mode uint

const (
    DefaultMode Mode = iota
    SM2Mode
    SM9Mode
)

func (this Mode) OidData() asn1.ObjectIdentifier {
    switch this {
        case SM2Mode:
            return oidSM2Data
        case SM9Mode:
            return oidSM9Data
        default:
            return oidData
    }
}

func (this Mode) IsData(oid asn1.ObjectIdentifier) bool {
    switch this {
        case SM2Mode:
            return oidSM2Data.Equal(oid)
        case SM9Mode:
            return oidSM9Data.Equal(oid)
        default:
            return oidData.Equal(oid)
    }
}

func (this Mode) OidSignedData() asn1.ObjectIdentifier {
    switch this {
        case SM2Mode:
            return oidSM2SignedData
        case SM9Mode:
            return oidSM9SignedData
        default:
            return oidSignedData
    }
}

func (this Mode) IsSignedData(oid asn1.ObjectIdentifier) bool {
    switch this {
        case SM2Mode:
            return oidSM2SignedData.Equal(oid)
        case SM9Mode:
            return oidSM9SignedData.Equal(oid)
        default:
            return oidSignedData.Equal(oid)
    }
}

func (this Mode) OidEnvelopedData() asn1.ObjectIdentifier {
    switch this {
        case SM2Mode:
            return oidSM2EnvelopedData
        case SM9Mode:
            return oidSM9EnvelopedData
        default:
            return oidEnvelopedData
    }
}

func (this Mode) IsEnvelopedData(oid asn1.ObjectIdentifier) bool {
    switch this {
        case SM2Mode:
            return oidSM2EnvelopedData.Equal(oid)
        case SM9Mode:
            return oidSM9EnvelopedData.Equal(oid)
        default:
            return oidEnvelopedData.Equal(oid)
    }
}

func (this Mode) OidSignedEnvelopedData() asn1.ObjectIdentifier {
    switch this {
        case SM2Mode:
            return oidSM2SignedEnvelopedData
        case SM9Mode:
            return oidSM9SignedEnvelopedData
        default:
            return oidSignedEnvelopedData
    }
}

func (this Mode) IsSignedEnvelopedData(oid asn1.ObjectIdentifier) bool {
    switch this {
        case SM2Mode:
            return oidSM2SignedEnvelopedData.Equal(oid)
        case SM9Mode:
            return oidSM9SignedEnvelopedData.Equal(oid)
        default:
            return oidSignedEnvelopedData.Equal(oid)
    }
}

func (this Mode) OidEncryptedData() asn1.ObjectIdentifier {
    switch this {
        case SM2Mode:
            return oidSM2EncryptedData
        case SM9Mode:
            return oidSM9EncryptedData
        default:
            return oidEncryptedData
    }
}

func (this Mode) IsEncryptedData(oid asn1.ObjectIdentifier) bool {
    switch this {
        case SM2Mode:
            return oidSM2EncryptedData.Equal(oid)
        case SM9Mode:
            return oidSM9EncryptedData.Equal(oid)
        default:
            return oidEncryptedData.Equal(oid)
    }
}
