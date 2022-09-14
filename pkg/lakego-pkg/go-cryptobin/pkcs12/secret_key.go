package pkcs12

type SecretKey interface {
    // Attributes return the PKCS12AttrSet of the safe bag
    // https://tools.ietf.org/html/rfc7292#section-4.2
    Attributes() map[string]string
    // key
    Key() []byte
    // FriendlyName return the value of `friendlyName`
    // attribute if exists, otherwise it will return empty string
    FriendlyName() string
}

type secretkey struct {
    attrs map[string]string
    key   []byte
}

func (this secretkey) Attributes() map[string]string {
    return this.attrs
}

func (this secretkey) Key() []byte {
    return this.key
}

func (this secretkey) FriendlyName() string {
    return this.attrs["friendlyName"]
}
