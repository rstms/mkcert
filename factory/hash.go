/*

 adapted from: https://github.com/na4ma4/go-ssl-subject-hash

 LICENSED GPL3 by author

 reference: https://stackoverflow.com/questions/40723858/java-1-7-subject-hash-of-x-509-certificate-openssl-1-0-compatible

*/

package factory

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ErrInvalidCertificate is returned when an invalid certificate is supplied.
var ErrInvalidCertificate = errors.New("invalid certificate")

// SubjHash is the certificate hash with fmt.Stringer interface support.
type SubjHash [4]byte

func (s SubjHash) String() string {
	return fmt.Sprintf("%x", [4]byte(s))
}

// Issuer takes a *x509.Certificate and returns the openssl 1.0.1+ compatible
// issuer_hash for the certificate.
func IssuerHash(cert *x509.Certificate) (SubjHash, error) {
	if cert == nil {
		return SubjHash{}, ErrInvalidCertificate
	}

	return hashRawValue(cert.RawIssuer)
}

func CertificateIssuerHash(certFile string) (string, error) {
	cert, err := ReadCertificate(certFile)
	if err != nil {
		return "", Fatal(err)
	}
	hash, err := IssuerHash(cert)
	if err != nil {
		return "", Fatal(err)
	}
	return hash.String(), nil
}

func CertificateSubjectHash(certFile string) (string, error) {
	cert, err := ReadCertificate(certFile)
	if err != nil {
		return "", Fatal(err)
	}
	hash, err := SubjectHash(cert)
	if err != nil {
		return "", Fatal(err)
	}
	return hash.String(), nil
}

// Subject takes a *x509.Certificate and returns the openssl 1.0.1+ compatible
// subject_hash for the certificate.
func SubjectHash(cert *x509.Certificate) (SubjHash, error) {
	if cert == nil {
		return SubjHash{}, ErrInvalidCertificate
	}

	return hashRawValue(cert.RawSubject)
}

func lowerCaseString(input string) string {
	output := ""

	for _, runeValue := range input {
		if runeValue >= utf8.RuneSelf {
			output += fmt.Sprintf("%c", runeValue)

			continue
		}

		if 'A' <= runeValue && runeValue <= 'Z' {
			runeValue += 'a' - 'A'
			output += fmt.Sprintf("%c", runeValue)

			continue
		}

		output += fmt.Sprintf("%c", runeValue)
	}

	return output
}

func hashRawValue(v []byte) (SubjHash, error) {
	var (
		subject pkix.RDNSequence
		hash    [4]byte
	)

	re := regexp.MustCompile(`\s+`)

	if _, err := asn1.UnmarshalWithParams(v, &subject, "utf8"); err != nil {
		return hash, Fatalf("unable to unmarshal ASN.1 subject: %v", err)
	}

	sb := bytes.NewBuffer(nil)

	for j := range subject {
		for i := range subject[j] {
			if v, ok := subject[j][i].Value.(string); ok {
				subject[j][i].Value = lowerCaseString(strings.TrimSpace(re.ReplaceAllString(v, " ")))
			}
		}

		b, err := remarshalASN1(subject[j])
		if err != nil {
			return hash, Fatalf("unable to remarshal ASN.1 RDN segment: %v", err)
		}

		if _, err = sb.Write(b); err != nil {
			return hash, Fatalf("unable to write bytes to buffer: %v", err)
		}
	}

	h := sha1.Sum(sb.Bytes())
	for i := range 4 {
		hash[3-i] = h[i]
	}

	return hash, nil
}

func remarshalASN1(val interface{}) ([]byte, error) {
	b, err := asn1.Marshal(val)
	if len(b) > 9 && b[4] == asn1.TagOID {
		offset := int(b[5])
		if len(b) > 6+offset && b[6+offset] == asn1.TagPrintableString {
			b[6+offset] = asn1.TagUTF8String
		}
	}

	return b, err
}
