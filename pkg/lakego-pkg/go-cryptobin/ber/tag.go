package ber

type Tag uint

const (
    TagEndOfContent     Tag = 0x00
    TagBoolean          Tag = 0x01
    TagInteger          Tag = 0x02
    TagBitString        Tag = 0x03
    TagOctetString      Tag = 0x04
    TagNull             Tag = 0x05
    TagObjectIdentifier Tag = 0x06
    TagObjectDescriptor Tag = 0x07
    TagExternal         Tag = 0x08
    TagReal             Tag = 0x09
    TagEnumerated       Tag = 0x0a
    TagEmbeddedPDV      Tag = 0x0b
    TagUTF8String       Tag = 0x0c
    TagRelativeOID      Tag = 0x0d
    TagTime             Tag = 0x0e

    TagSequence        Tag = 0x10
    TagSequenceOf      Tag = TagSequence
    TagSet             Tag = 0x11
    TagSetOf           Tag = TagSet
    TagNumericString   Tag = 0x12
    TagPrintableString Tag = 0x13
    TagT61String       Tag = 0x14
    TagVideotexString  Tag = 0x15
    TagIA5String       Tag = 0x16
    TagUTCTime         Tag = 0x17
    TagGeneralizedTime Tag = 0x18
    TagGraphicString   Tag = 0x19
    TagVisibleString   Tag = 0x1a
    TagGeneralString   Tag = 0x1b
    TagUniversalString Tag = 0x1c
    TagCharacterString Tag = 0x1d
    TagBMPString       Tag = 0x1e
)

type TagClass uint8

const (
    TagClassUniversal       TagClass = 0
    TagClassApplication     TagClass = 1
    TagClassContextSpecific TagClass = 2
    TagClassPrivate         TagClass = 3
)
