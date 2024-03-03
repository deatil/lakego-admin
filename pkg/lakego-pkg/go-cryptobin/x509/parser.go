package x509

import (
    "net"
    "fmt"
    "errors"
    "strings"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func parseNameConstraintsExtension(out *Certificate, e pkix.Extension) (unhandled bool, err error) {
    // RFC 5280, 4.2.1.10

    // NameConstraints ::= SEQUENCE {
    //      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
    //      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
    //
    // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
    //
    // GeneralSubtree ::= SEQUENCE {
    //      base                    GeneralName,
    //      minimum         [0]     BaseDistance DEFAULT 0,
    //      maximum         [1]     BaseDistance OPTIONAL }
    //
    // BaseDistance ::= INTEGER (0..MAX)

    outer := cryptobyte.String(e.Value)
    var toplevel, permitted, excluded cryptobyte.String
    var havePermitted, haveExcluded bool
    if !outer.ReadASN1(&toplevel, cryptobyte_asn1.SEQUENCE) ||
        !outer.Empty() ||
        !toplevel.ReadOptionalASN1(&permitted, &havePermitted, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) ||
        !toplevel.ReadOptionalASN1(&excluded, &haveExcluded, cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) ||
        !toplevel.Empty() {
        return false, errors.New("x509: invalid NameConstraints extension")
    }

    if !havePermitted && !haveExcluded || len(permitted) == 0 && len(excluded) == 0 {
        // From RFC 5280, Section 4.2.1.10:
        //   “either the permittedSubtrees field
        //   or the excludedSubtrees MUST be
        //   present”
        return false, errors.New("x509: empty name constraints extension")
    }

    getValues := func(subtrees cryptobyte.String) (dnsNames []string, ips []*net.IPNet, emails, uriDomains []string, err error) {
        for !subtrees.Empty() {
            var seq, value cryptobyte.String
            var tag cryptobyte_asn1.Tag
            if !subtrees.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
                !seq.ReadAnyASN1(&value, &tag) {
                return nil, nil, nil, nil, fmt.Errorf("x509: invalid NameConstraints extension")
            }

            var (
                dnsTag   = cryptobyte_asn1.Tag(2).ContextSpecific()
                emailTag = cryptobyte_asn1.Tag(1).ContextSpecific()
                ipTag    = cryptobyte_asn1.Tag(7).ContextSpecific()
                uriTag   = cryptobyte_asn1.Tag(6).ContextSpecific()
            )

            switch tag {
            case dnsTag:
                domain := string(value)
                if err := isIA5String(domain); err != nil {
                    return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
                }

                trimmedDomain := domain
                if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
                    // constraints can have a leading
                    // period to exclude the domain
                    // itself, but that's not valid in a
                    // normal domain name.
                    trimmedDomain = trimmedDomain[1:]
                }
                if _, ok := domainToReverseLabels(trimmedDomain); !ok {
                    return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse dnsName constraint %q", domain)
                }
                dnsNames = append(dnsNames, domain)

            case ipTag:
                l := len(value)
                var ip, mask []byte

                switch l {
                case 8:
                    ip = value[:4]
                    mask = value[4:]

                case 32:
                    ip = value[:16]
                    mask = value[16:]

                default:
                    return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained value of length %d", l)
                }

                if !isValidIPMask(mask) {
                    return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained invalid mask %x", mask)
                }

                ips = append(ips, &net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)})

            case emailTag:
                constraint := string(value)
                if err := isIA5String(constraint); err != nil {
                    return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
                }

                // If the constraint contains an @ then
                // it specifies an exact mailbox name.
                if strings.Contains(constraint, "@") {
                    if _, ok := parseRFC2821Mailbox(constraint); !ok {
                        return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
                    }
                } else {
                    // Otherwise it's a domain name.
                    domain := constraint
                    if len(domain) > 0 && domain[0] == '.' {
                        domain = domain[1:]
                    }
                    if _, ok := domainToReverseLabels(domain); !ok {
                        return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
                    }
                }
                emails = append(emails, constraint)

            case uriTag:
                domain := string(value)
                if err := isIA5String(domain); err != nil {
                    return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
                }

                if net.ParseIP(domain) != nil {
                    return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q: cannot be IP address", domain)
                }

                trimmedDomain := domain
                if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
                    // constraints can have a leading
                    // period to exclude the domain itself,
                    // but that's not valid in a normal
                    // domain name.
                    trimmedDomain = trimmedDomain[1:]
                }
                if _, ok := domainToReverseLabels(trimmedDomain); !ok {
                    return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q", domain)
                }
                uriDomains = append(uriDomains, domain)

            default:
                unhandled = true
            }
        }

        return dnsNames, ips, emails, uriDomains, nil
    }

    if out.PermittedDNSDomains, out.PermittedIPRanges, out.PermittedEmailAddresses, out.PermittedURIDomains, err = getValues(permitted); err != nil {
        return false, err
    }
    if out.ExcludedDNSDomains, out.ExcludedIPRanges, out.ExcludedEmailAddresses, out.ExcludedURIDomains, err = getValues(excluded); err != nil {
        return false, err
    }
    out.PermittedDNSDomainsCritical = e.Critical

    return unhandled, nil
}

func parseCertificatePoliciesExtension(der cryptobyte.String) ([]asn1.ObjectIdentifier, error) {
    var oids []asn1.ObjectIdentifier
    if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
        return nil, errors.New("x509: invalid certificate policies")
    }

    for !der.Empty() {
        var cp cryptobyte.String
        if !der.ReadASN1(&cp, cryptobyte_asn1.SEQUENCE) {
            return nil, errors.New("x509: invalid certificate policies")
        }
        var oid asn1.ObjectIdentifier
        if !cp.ReadASN1ObjectIdentifier(&oid) {
            return nil, errors.New("x509: invalid certificate policies")
        }
        oids = append(oids, oid)
    }

    return oids, nil
}
