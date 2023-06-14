package asn1

type Tag uint

const (
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
    TagEmbeddedPdv      Tag = 0x0b
    TagUtf8String       Tag = 0x0c
    TagRelativeOid      Tag = 0x0d
    TagTime             Tag = 0x0e
    TagSequence         Tag = 0x10
    TagSequenceOf       Tag = 0x10
    TagSet              Tag = 0x11
    TagSetOf            Tag = 0x11
    TagNumericString    Tag = 0x12
    TagPrintableString  Tag = 0x13
    TagT61String        Tag = 0x14
    TagVideotexString   Tag = 0x15
    TagIa5String        Tag = 0x16
    TagUtcTime          Tag = 0x17
    TagGeneralizedTime  Tag = 0x18
    TagGraphicString    Tag = 0x19
    TagVisibleString    Tag = 0x1a
    TagGeneralString    Tag = 0x1b
    TagUniversalString  Tag = 0x1c
    TagCharacterString  Tag = 0x1d
    TagBmpString        Tag = 0x1e
    TagDate             Tag = 0x1f
    TagTimeOfDay        Tag = 0x20
    TagDateTime         Tag = 0x21
    TagDuration         Tag = 0x22
    TagOidIri           Tag = 0x23
    TagRelativeOidIri   Tag = 0x24
)

type TagClass uint8

const (
    TagClassUniversal       TagClass = 0x00
    TagClassApplication     TagClass = 0x01
    TagClassContextSpecific TagClass = 0x02
    TagClassPrivate         TagClass = 0x03
)
