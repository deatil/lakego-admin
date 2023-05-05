# asn1

[ASN.1](https://en.wikipedia.org/wiki/ASN.1) [BER](https://en.wikipedia.org/wiki/X.690#BER_encoding) serialization Go module.

## Basic Encoding Rules (BER)

BER uses a [type-length-value](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value) encoding scheme. Encoded data will be structured as follows:

![](docs/encoding.png)

The **Identifier octets** identify the *type* of thing encoded. The **Length octets** identify the *length* of the thing encoded. Finally, the **Content octets** contain the *encoded thing*.

## Identifier octets

The identifier octets encode the ASN.1 tag class, whether it is primitive or constructed, and tag number.

![](docs/identifier-octet.png)

### Class

The tag's class is set in bits 8 and 7 in the first octet. Possible values:

|Class|Bit 8|Bit 7|
|-|-|-|
|Universal|0|0|
|Application|0|1|
|Context-specific|1|0|
|Private|1|1|

### Primitive/Constructed

Bit 6 sets whether the value is primitive or constructed:

|Bit 6 value||
|-|-|
|0|primitive|
|1|constructed|

Primitive encodings represent the value directly. For instance, an `INTEGER` tag is primitive, and the underlying content value is an encoded integer.

Constructed encodings represent a concatenation of other encoded values.

### Tag number

For tag numbers <= 30 (the universal tags), the last 5 bits are used to encode the tag number, and the identifier will be 1 octet total. For tag numbers >= 31 the last 5 bits of the first octet are encoded to `11111`. The subsequent octets are then the base 128 encoding of the tag number.

## Length octets

BER supports length octets in two possible forms: definite and indefinite. **This module only supports the definite form.**

## Content Encoding

### Types

|ASN.1 Type|Description|Tag|Go Types|
|-|-|-|-|
|`BOOLEAN`|Simple boolean value|1|`bool`|
|`INTEGER`|A signed integer value, with no limits|2|`int`, `int8`, `int16`, `int32`, `int64`|
|`BIT STRING`|Arbitrary string of bits|3||
|`OCTET STRING`|A value of zero or more bytes|4|`[]byte`|
|`OBJECT IDENTIFIER`||6|`ObjectIdentifier`|
|`REAL`||9|`float32`, `float64`|
|`Strings`|[See below](#strings)|[See below](#strings)|`string`|

### Strings

ASN.1 has many string types:

|Type|Tag|Description|
|-|-|-|
|`BMPString`|30||
|`GeneralString`|27||
|`GraphicString`|25||
|`IA5String`|22|First 128 chracters of ASCII alphabet|
|`NumericString`|18||
|`PrintableString`|19|A restricted subset of ASCII alphabet|
|`T61String`|20||
|`UniversalString`|28||
|`UTF8String`|12||
|`VideotexString`|21||
|`VisibleString`|26||


## Explicit/Implicit Tags

ASN.1 has `IMPLICIT` and `EXPLICIT` tags. 

`IMPLICIT` tags are derived from other types by changing the tag of the underlying type. ASN.1 notation:

**[*[class]* *number*]** `IMPLICIT` ***Type***

***class = *** `UNIVERSAL` | `APPLICATION` | `PRIVATE`

**Note**: The `IMPLICIT` keyword is optional in ASN.1 modules.

If there is no class name, the tag's class is Context-specific (which can only be a component of a structured or `CHOICE` type).

### Implicit Exaple

ASN.1 notation:

```asn1
[5] IMPLICIT UTF8String
```

1. Encode "hi"
2. The identifier octet would be encoded as:
   1. `10` - Context-specific defaults
   2. `0` - primitive
   3. `101` - 5

## Todo

* Handle pointers
