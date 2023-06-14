# ASN.1

```
 █████  ███████ ███    ██     ██ 
██   ██ ██      ████   ██    ███ 
███████ ███████ ██ ██  ██     ██ 
██   ██      ██ ██  ██ ██     ██ 
██   ██ ███████ ██   ████ ██  ██ 

BER encoder/decoder
```

Encoding and decoding of ASN.1 (Abstract Syntax Notation One) (X.208) abstract objects using BER (Basic Encoding Rules) (X.209).

## Basic Encoding Rules

A BER encoding consists of 3 components:

* *Identifier* octets
* *Length* octets
* *Contents* octets

### Identifier octets

The identifier octets encode the ASN.1 tag (class and number) of the type of the data value.

#### Low Tags (0 - 30)

Single octet

* Bits 8 + 7: [class of the tag](#tag-class)
* Bit 6: `0` if primitive, `1` if constructed
* Bit 5 - 1: tag number, encoded as a binary integer

#### High Tags (>= 31)

2+ octets

* Bit 8 + 7: [class of the tag](#tag-class)
* Bit 6: `0` if primitive, `1` if constructed
* Bits 5 - 1: `11111`
* 2nd octet: tag number [**base-128**](#base-128) encoded

### Length octets

Can be in **definite** and **indefinite** form. We don't use **indefinite**.

#### Definite form

* 1 or more octets
* Represents the number of octets in the contetns octets
* Can be in **short** or **long** form

##### Short form

Contents octets <= 127

* Single octet
* Bit 8: `0`
* Bits 7 - 1: Number of content octets (may be zero), as an unsigned bianry integer

Example:

Number of content octets = 38

**Short from length encoding**: `b00100110`

##### Long form

Contents octets > 127

* Initial octet + one or more subsequent octets
* Initial octet
  * Bit 8: `1`
  * Bit 7 - 1: Number of subsequent octets in length octets, as an unsigned binary integer
  * Value `b11111111` cannot be used
* Subsequent octets
  * Encoding of unsigned binary integer equal to the number of content octets

Example:

Number of content octets = 201

**Long from length encoding**: `0b10000001 0b11001001`

### Tag Class

|**Class**|**Bit 8**|**Bit 7**|**Definition**|
|-|-|-|-|
|Universal|`0`|`0`|Meaning is the same in all applications|
|Application|`0`|`1`|Meaning is specific to an application (i.e. LDAP)|
|Context-specific|`1`|`0`|Meaning is specific to a particular usage within a given application.|
|Private|`1`|`1`|Meaning is specific to a given enterprise|

### Base-128

For each octet:

* Bit 8: `1`, except last octet
* Bit 7 - 1: encoding of the unsigned binary integer

Bits 7 - 1 of the first subsequent octet cannot be all zero.

### Universal types

* `BIT STRING`: an arbitrary string of bits.
* `IA5String`: an arbitrary string of IA5 (ASCII) characters.
* `INTEGER`: an arbitrary integer.
* `NULL`: a null value.
* `OBJECT IDENTIFIER`: an [object identifier](https://en.wikipedia.org/wiki/Object_identifier)
* `OCTET STRING`: an arbitrary string of octets.
* `PrintableString`: an arbitrary string of printable characters.
* `T61String`: an arbitrary string of T.61 characters.
* `UTCTime`: a [UTC](https://en.wikipedia.org/wiki/Coordinated_Universal_Time) timestamp

#### Structured types

* `SEQUENCE`: *ordered* collection of items of *one or more types*
* `SEQUENCE OF`: *ordered* collection of *zero or more* items of the *same type*
* `SET`: *unordered* collection of items of *one or more types*
* `SET OF` *unordered* collection of *zero or more* items of the *same type*

### Implicity and explicity tagged types

**Implicitly** tagged types are derived from other types by changing the tag of the underlying type.

**Explicitly** tagged types are derived from other types by adding an outer tag to the underlying type. Effectively a structured type consisting of one component: the underlying type.

These can be translated as:

`IMPLICIT`: *instead of*

`EXPLICIT`: *in addition to*

****EXPLICIT** is the default.**

### Type Encodings

#### `BIT STRING`

**Primitive *or* constructed**.

**Constructed not supported**.

`BIT STRING` is an arbitrary string of bits. Can have any length, including zero.

The first contents octets give the number of unused bits. The second and following contents octets give the value of the bit string, converted to an octet string.

The bit string is padded after the last bit with zero to seven bits to make the length of the bit string a multiple of eight (so no padding if the length already is a multiple of eight).

Example: `011011100101110111` -> `01101110 01011101 11000000` (`6e 5d c0`) (6 unused bits)

Then in Go:

```go
bitString, _ := NewBitString([]byte{0x6e, 0x5d, 0xc0}, 6)
```

#### `IA5String`

**Primitive *or* constructed**.

**Constructed not supported**.

`IA5String` is an arbitrary string of IA5 characters (ASCII).

#### `INTEGER`

**Primitive**

`INTEGER` is an arbitrary integer. Contents octets are the value of the integer, base-256, two's complement form, big-endian, with minimum number of octets.

#### `ENUMERATED`

Encoding is exactly the same as an `INTEGER`.

#### `NULL`

**Primitive**

`NULL` denotes a null value. Contents octets are empty.

#### `OBJECT IDENTIFIER`

**Primitive**

`OBJECT IDENTIFIER` denotes an [object identifier](https://en.wikipedia.org/wiki/Object_identifier).

The first octet has the value `40 * oid[0] + oid[1]`. `oid[0]` is limited to 0, 1 and 2. `oid[1]` is limited to 0 to 39 when `oid[0]` is 0 or 1.

The following octets are each value encoded, base-128, big-endian, with minimum number of octets. The most significant bit of each octet, except the last, must be 1.

#### `OCTET STRING`

**Primitive *or* constructed**.

**Constructed not supported**.

`OCTET STRING` denotes an arbitrary string of octets.

The encoding is the value of the octet string.

#### `PrintableString`

**Primitive *or* constructed**.

**Constructed not supported**.

`PrintableString` is an arbitrary string of printable characters from the following set:

```
A, B, ..., Z
a, b, ..., z
0, 1, ..., 9
(space) ' ( ) + , - . / : = ?
```

#### `SEQUENCE`

**Constructed**

`SEQUENCE` denotes an **ordered** collection of **one or more types**.

Contents octets are the concatenation of the BER encodings of the values of the components of the sequence, in order of definition.

If a compnent has an `OPTIONAL` or `DEFAULT` qualifier, and is absent from the sequence during encoding, that component is not included in the contents octets. If the compnent with a `DEFAULT` qualifier is the default value during the encoding, it may or may not be included in the contents octets.

#### `SEQUENCE OF`

**Constructed**

`SEQUENCE OF` denotes an **ordered** collection of **zero or more occurrences of a given type**.

Contents octets are the concatenation of the BER encodings of the values of the components of the sequence, in order of definition.

#### `SET`

**Constructed**

`SET` denotes an **unordered** collection of **one or more types**.

Contents octets are the concatenation of the BER encodings of the values of the components of the set, in any order.

If a compnent has an `OPTIONAL` or `DEFAULT` qualifier, and is absent from the sequence during encoding, that component is not included in the contents octets. If the compnent with a `DEFAULT` qualifier is the default value during the encoding, it may or may not be included in the contents octets.

#### `SET OF`

**Constructed**

`SET OF` denotes an **unordered** collection of **zero or more occurrences of a given type**.

Contents octets are the concatenation of the BER encodings of the values of the components of the set, in any order.

#### `T61String`

**Primitive *or* constructed**.

**Constructed not supported**.

`T61String` is an arbitrary string of [T.61 characters](https://en.wikipedia.org/wiki/ITU_T.61).

#### `UTCTime`

**Primitive *or* constructed**.

**Constructed not supported**.

`UTCTime` denotes a [UTC](https://en.wikipedia.org/wiki/Coordinated_Universal_Time) timestamp. Can be in the following formats:

```
YYMMDDhhmmZ
YYMMDDhhmm+hh'mm'
YYMMDDhhmm-hh'mm'
YYMMDDhhmmssZ
YYMMDDhhmmss+hh'mm'
YYMMDDhhmmss-hh'mm'
```

It is encoded as an ASCII string.

Example:

**May 6, 1991 4:45:40 PM PDT**

Can be formatted as:

* `910506164540-0700`
* `910506234540Z`

## References

[ITU-T X.690 - BER spec](https://www.itu.int/rec/T-REC-X.690/)

[A Layman's Guide to a Subset of ASN.1, BER, and DER](https://luca.ntop.org/Teaching/Appunti/asn1.html)

[Basic Encoding Rules - Sun OpenDS Standard Edition 2.2 Glossary of LDAP and Directory Terminology](https://docs.oracle.com/cd/E19476-01/821-0510/def-basic-encoding-rules.html)

[LDAPv3 Wire Protocol Reference: The ASN.1 Basic Encoding Rules](https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/)

[X.690 - Wikipedia](https://en.wikipedia.org/wiki/X.690)

[A Warm Welcome to ASN.1 and DER](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/)

[ASN.1 by simple words - Yury Strozhevsky](https://www.strozhevsky.com/free_docs/asn1_by_simple_words.pdf)

### Books

[ASN.1 Communication Between Heterogeneous Systems - Olivier Dubuisson](https://www.oss.com/asn1/resources/books-whitepapers-pubs/dubuisson-asn1-book.PDF)

[ASN.1 Complete - John Larmouth](https://www.oss.com/asn1/resources/books-whitepapers-pubs/larmouth-asn1-book.pdf)

### Tools

[ASN.1 JavaScript decoder](https://lapo.it/asn1js)

[ASN.1 Playground](https://asn1.io/asn1playground/)
