package factory

import (
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

func initFactory(t *testing.T) *CertFactory {
	Init("test", Version, filepath.Join("testdata", "config.yaml"))
	ViperSet("mkcert.keymaster", filepath.Join("testdata", "keymaster.pem"))
	ViperSet("mkcert.config_dir", filepath.Join("testdata", "config"))
	ViperSet("mkcert.cache_dir", filepath.Join("testdata", "cache"))
	f, err := NewCertFactory(nil)
	require.Nil(t, err)
	return f
}

func TestFactoryInit(t *testing.T) {
	f := initFactory(t)
	require.NotNil(t, f)
}

func TestFactoryKeypair(t *testing.T) {
	f := initFactory(t)
	require.NotNil(t, f)

	certsDir := filepath.Join("testdata", "certs")

	certFile := filepath.Join(certsDir, "cert.pem")
	if IsFile(certFile) {
		err := os.Remove(certFile)
		require.Nil(t, err)
	}

	keyFile := filepath.Join(certsDir, "key.pem")
	if IsFile(keyFile) {
		err := os.Remove(keyFile)
		require.Nil(t, err)
	}

	cert, key, err := f.CertificatePair("testcert", "10m", certFile, keyFile)
	require.Nil(t, err)

	require.Equal(t, certFile, cert)
	require.True(t, IsFile(certFile))

	require.Equal(t, keyFile, key)
	require.True(t, IsFile(keyFile))

	cmd := exec.Command("openssl", "x509", "-in", certFile, "-noout", "-text")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	require.Nil(t, err)
}

func TestFactoryHash(t *testing.T) {
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
	hash, err := CertHash(certFile)
	require.Nil(t, err)
	match := regexp.MustCompile("^[a-fA-F0-9]{8}$").MatchString(hash)
	require.True(t, match)
	log.Printf("hash=%s\n", hash)
}
