package factory

import (
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func mkTestCert(t *testing.T) string {
	f := initFactory(t)
	require.NotNil(t, f)
	certFile := filepath.Join("testdata", "certs", "hashroot.pem")
	if IsFile(certFile) {
		err := os.Remove(certFile)
		require.Nil(t, err)
	}
	outFile, err := f.Root(certFile)
	require.Nil(t, err)
	require.Equal(t, certFile, outFile)
	return certFile
}

func TestFactoryHash(t *testing.T) {
	certFile := mkTestCert(t)
	newHash, err := CertificateSubjectHash(certFile)
	require.Nil(t, err)
	newMatch := regexp.MustCompile("^[a-fA-F0-9]{8}$").MatchString(newHash)
	require.True(t, newMatch)
	log.Printf("new_hash=%s\n", newHash)

}
