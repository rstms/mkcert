/*
Copyright © 2024 Matt Krueger <mkrueger@rstms.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package factory

import (
	"bufio"
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Version = "0.2.13"

//go:embed default_keymaster_config.yaml
var defaultKeymasterConfig string

var emojiPattern = regexp.MustCompile(`(?:[` +
	`\x{2600}-\x{26FF}` + // Miscellaneous Symbols
	`\x{2700}-\x{27BF}` + // Dingbats
	`\x{FE00}-\x{FE0F}` + // Variation Selectors
	`\x{1F1E6}-\x{1F1FF}` + // Regional Indicator Symbols
	`\x{1F300}-\x{1F5FF}` + // symbols & pictographs
	`\x{1F600}-\x{1F64F}` + // emoticons
	`\x{1F680}-\x{1F6FF}` + // transport & map symbols
	`\x{1F700}-\x{1F77F}` + // alchemical symbols
	`\x{1F780}-\x{1F7FF}` + // Geometric Shapes Extended
	`\x{1F800}-\x{1F8FF}` + // Supplemental Arrows-C
	`\x{1F900}-\x{1F9FF}` + // Supplemental Symbols and Pictographs
	`\x{1FA00}-\x{1FAFF}` + // Chess Symbols and others
	`])`)

var ansiEscapePattern = regexp.MustCompile(`\x1B\[[;?0-9]*[mK]`)

type StepConfig struct {
	URL         string //json: `"ca_url"`
	Fingerprint string //json: `"fingerprint"`
	Root        string //json: `"root"`
}

type KeymasterConfig struct {
	Hostname string
	Port     int
	Path     string
	Subject  string
	Issuer   string
}

type KeyType int

const (
	KeyTypeRSA = iota
	KeyTypeECURVE
	KeyTypeED25519
)

type CertFactory struct {
	Version            string
	Debug              bool
	Verbose            bool
	Raw                bool
	TTY                bool
	Overwrite          bool
	StepBinary         string
	DefaultDuration    string
	StepTimeoutSeconds int64
	StepArgs           []string
	KeyType            KeyType
	PasswordFile       string
	Issuer             string
	Fingerprint        string
	CaURL              string
	RootCA             string
	ConfigDir          string
	CacheDir           string
}

func NewCertFactory(stepArgs *[]string) (*CertFactory, error) {
	prefix := "mkcert."
	if ProgramName() == "mkcert" {
		prefix = ""
	}
	ViperSetDefault(prefix+"timeout_seconds", 3)

	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return nil, Fatal(err)
	}
	ViperSetDefault(prefix+"config_dir", filepath.Join(userConfigDir, ProgramName()))

	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, Fatal(err)
	}
	ViperSetDefault(prefix+"cache_dir", filepath.Join(userCacheDir, ProgramName()))

	configDir := ViperGetString(prefix + "config_dir")
	ViperSetDefault(prefix+"password_file", filepath.Join(configDir, "mkcert_password"))

	ViperSetDefault(prefix+"default_duration", "5m")
	f := CertFactory{
		Version:            Version,
		PasswordFile:       ViperGetString(prefix + "password_file"),
		Debug:              ViperGetBool(prefix + "debug"),
		Verbose:            ViperGetBool(prefix + "verbose"),
		Overwrite:          ViperGetBool(prefix + "overwrite"),
		Raw:                ViperGetBool(prefix + "echo_raw"),
		TTY:                ViperGetBool(prefix + "echo_tty"),
		StepBinary:         ViperGetString(prefix + "step_command"),
		StepTimeoutSeconds: ViperGetInt64(prefix + "timeout_seconds"),
		StepArgs:           []string{},
		DefaultDuration:    ViperGetString(prefix + "default_duration"),
		KeyType:            KeyTypeRSA,
		Issuer:             ViperGetString(prefix + "issuer"),
		CaURL:              ViperGetString(prefix + "ca_url"),
		Fingerprint:        ViperGetString(prefix + "fingerprint"),
		RootCA:             ViperGetString(prefix + "root_cert"),
		ConfigDir:          ViperGetString(prefix + "config_dir"),
		CacheDir:           ViperGetString(prefix + "cache_dir"),
	}

	if !IsDir(f.ConfigDir) {
		err := os.MkdirAll(f.ConfigDir, 0700)
		if err != nil {
			return nil, Fatal(err)
		}
	}

	if !IsDir(f.CacheDir) {
		err := os.MkdirAll(f.CacheDir, 0700)
		if err != nil {
			return nil, Fatal(err)
		}
	}

	if f.StepBinary == "" || !IsFile(f.StepBinary) {
		bin, err := f.installStepBinary()
		if err != nil {
			return nil, err
		}
		f.StepBinary = bin
		ViperSet(prefix+"step_command", bin)
	}

	if f.CaURL == "" || f.Fingerprint == "" || f.RootCA == "" || f.Issuer == "" {
		keymaster := ViperGetString(prefix + "keymaster")
		if keymaster != "" && IsFile(keymaster) {
			err := f.initFromKeymaster(keymaster)
			if err != nil {
				return nil, err
			}
		}
	}

	if f.CaURL == "" || f.Fingerprint == "" || f.RootCA == "" {
		// try reading the ~/.step config
		err = f.initFromStepConfig()
		if err != nil {
			return nil, Fatal(err)
		}
	}

	// if issuer or caURL are still unset, try setting domain-based values
	if f.Issuer == "" || f.CaURL == "" {

		// FIXME: Hostname won't return the domain on windows

		hostname, err := os.Hostname()
		if err != nil {
			return nil, err
		}

		domain := hostname
		host, domain, ok := strings.Cut(hostname, ".")
		if !ok {
			domain = host
		}
		if strings.Contains(domain, ".") {
			if f.Issuer == "" {
				f.Issuer = "keymaster@" + domain
				ViperSet(prefix+"issuer", f.Issuer)
			}
			if f.CaURL == "" {
				f.CaURL = "https://keymaster." + domain
				ViperSet(prefix+"ca_url", f.CaURL)
			}
		}
	}

	if f.CaURL == "" {
		return nil, Fatalf("missing config: ca_url")
	}

	_, err = url.Parse(f.CaURL)
	if err != nil {
		return nil, Fatalf("failed parsing ca_url '%s': %v", f.CaURL, err)
	}

	if ViperGetString(prefix+"ca_url") == "" {
		ViperSet(prefix+"ca_url", f.CaURL)
	}

	if f.Fingerprint == "" {
		return nil, Fatalf("missing config: fingerprint")
	}

	if ViperGetString(prefix+"fingerprint") == "" {
		ViperSet(prefix+"fingerprint", f.Fingerprint)
	}

	if f.RootCA == "" {
		return nil, Fatalf("missing config: root_cert")

	}

	if !IsFile(f.RootCA) {
		return nil, Fatalf("root_cert %s is not a file", f.RootCA)
	}

	if ViperGetString(prefix+"root_cert") == "" {
		ViperSet(prefix+"root_cert", f.RootCA)
	}

	if f.Issuer == "" {
		return nil, Fatalf("missing config: issuer")
	}

	if ViperGetString(prefix+"issuer") == "" {
		ViperSet(prefix+"issuer", f.Issuer)
	}

	if f.PasswordFile == "" {
		return nil, Fatalf("missing config: password_file")

	}

	if !IsFile(f.PasswordFile) {
		return nil, Fatalf("password_file %s is not a file", f.PasswordFile)
	}

	// add passed-in stepArgs if any
	if stepArgs != nil {
		f.StepArgs = append(f.StepArgs, *stepArgs...)
	}

	if f.Debug {
		log.Printf("NewCertFactory: %s\n", FormatJSON(f))
	}
	return &f, nil
}

func (c *CertFactory) initFromKeymaster(keymasterFile string) error {
	// extract the root cert from keymaster (it may be a chain)

	if c.RootCA == "" {
		rootData, err := c.runStep("certificate", "inspect", "--format=pem", keymasterFile)
		if err != nil {
			return Fatal(err)
		}
		c.RootCA = filepath.Join(c.ConfigDir, "root.pem")
		err = os.WriteFile(c.RootCA, rootData, 0600)
		if err != nil {
			return Fatal(err)
		}
	}

	if c.Fingerprint == "" {
		fpData, err := c.runStep("certificate", "fingerprint", c.RootCA)
		if err != nil {
			return Fatal(err)
		}
		c.Fingerprint = string(fpData)
	}

	keymasterConfigFile := filepath.Join(c.ConfigDir, "keymaster.yaml")
	if !IsFile(keymasterConfigFile) {
		// create keymaster config file if not present
		err := os.WriteFile(keymasterConfigFile, []byte(defaultKeymasterConfig), 0600)
		if err != nil {
			return Fatal(err)
		}
	}
	kmData, err := os.ReadFile(keymasterConfigFile)
	if err != nil {
		return Fatal(err)
	}
	var keymasterConfig map[string]KeymasterConfig
	err = yaml.Unmarshal(kmData, &keymasterConfig)
	if err != nil {
		return Fatalf("failed decoding: %s: %v", keymasterConfigFile, err)
	}

	kmcfg, ok := keymasterConfig[c.Fingerprint]
	if ok {
		if c.CaURL == "" {
			// assemble URL from keymaster config
			var kmurl url.URL
			kmurl.Scheme = "https"
			if kmcfg.Port == 0 || kmcfg.Port == 443 {
				kmurl.Host = kmcfg.Hostname
			} else {
				kmurl.Host = fmt.Sprintf("%s:%d", kmcfg.Hostname, kmcfg.Port)
			}
			kmurl.Path = kmcfg.Path
			// test for valid URL
			c.CaURL = kmurl.String()
		}

		if c.Issuer == "" {
			c.Issuer = kmcfg.Issuer
		}
		return nil
	}
	Warning("fingerprint %s not found in %s", c.Fingerprint, keymasterConfigFile)
	return nil
}

func (c *CertFactory) initFromStepConfig() error {
	stdout, err := c.runStep("path")
	if err != nil {
		return Fatalf("failed getting step config path: %v", err)
	}
	cfgPath := string(stdout)
	if cfgPath == "" || !IsDir(cfgPath) {
		Warning("no step config found")
		return nil
	}
	stepConfigFile := filepath.Join(cfgPath, "config", "defaults.json")
	data, err := os.ReadFile(stepConfigFile)
	if err != nil {
		return Fatal(err)
	}
	var config StepConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return Fatalf("failed parsing step config %s: %v", stepConfigFile, err)
	}
	if c.CaURL == "" {
		c.CaURL = config.URL
	}
	if c.Fingerprint == "" {
		c.Fingerprint = config.Fingerprint
	}
	if c.RootCA == "" {
		c.RootCA = config.Root
	}
	return nil
}

func (c *CertFactory) SetKeyType(keyType KeyType) {
	c.KeyType = keyType
}

func (c *CertFactory) Root(pathname string) (string, error) {
	certFile, _ := outputFiles(pathname)

	err := c.checkOutputFile(certFile)
	if err != nil {
		return "", err
	}

	args := []string{
		"ca", "root",
		"--force",
		"--ca-url", c.CaURL,
		"--fingerprint", c.Fingerprint,
		certFile,
	}
	args = append(args, c.StepArgs...)
	_, err = c.runStep(args...)
	if err != nil {
		return "", err
	}
	return certFile, nil
}

func outputFiles(pathname string) (string, string) {
	path, file := filepath.Split(pathname)
	base, _, _ := strings.Cut(file, ".")
	certFile := filepath.Join(path, base+".pem")
	keyFile := filepath.Join(path, base+".key")
	return certFile, keyFile
}

func (c *CertFactory) Chain(pathname string) (string, error) {

	certFile, keyFile, err := c.CertificatePair(pathname, "", "", "")
	if err != nil {
		return "", err
	}
	iLines, err := readCert(certFile, 1)
	if err != nil {
		return "", err
	}
	err = os.Remove(certFile)
	if err != nil {
		return "", err
	}
	err = os.Remove(keyFile)
	if err != nil {
		return "", err
	}
	rootFile, err := c.Root(pathname)
	if err != nil {
		return "", err
	}
	rLines, err := readCert(rootFile, 0)
	if err != nil {
		return "", err
	}
	ofp, err := os.Create(rootFile)
	if err != nil {
		return "", err
	}
	defer ofp.Close()
	for _, line := range rLines {
		fmt.Fprintf(ofp, "%s\n", line)
	}
	for _, line := range iLines {
		fmt.Fprintf(ofp, "%s\n", line)
	}
	return rootFile, nil
}

func (c *CertFactory) Intermediate(pathname string) (string, error) {

	certFile, keyFile, err := c.CertificatePair(pathname, "", "", "")
	if err != nil {
		return "", err
	}
	iLines, err := readCert(certFile, 1)
	if err != nil {
		return "", err
	}
	err = os.Remove(certFile)
	if err != nil {
		return "", err
	}
	err = os.Remove(keyFile)
	if err != nil {
		return "", err
	}

	ofp, err := os.Create(certFile)
	if err != nil {
		return "", err
	}
	defer ofp.Close()

	for _, line := range iLines {
		fmt.Fprintf(ofp, "%s\n", line)
	}
	return certFile, nil
}

func readCert(filename string, index int) ([]string, error) {
	lines := []string{}
	file, err := os.Open(filename)
	if err != nil {
		return lines, err
	}
	defer file.Close()
	var count int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if count == index {
			lines = append(lines, line)
		}
		if strings.Contains(line, "END CERTIFICATE") {
			count += 1
		}
	}
	err = scanner.Err()
	if err != nil {
		return lines, err
	}
	return lines, nil
}

func (c *CertFactory) CertificatePair(subjectName, duration, certFile, keyFile string) (string, string, error) {
	cmdArgs := []string{}
	if duration == "" {
		duration = c.DefaultDuration
	}

	subjectCertFile, subjectKeyFile := outputFiles(subjectName)

	if certFile == "" {
		certFile = subjectCertFile
	}
	if keyFile == "" {
		keyFile = subjectKeyFile
	}

	err := c.checkOutputFile(certFile)
	if err != nil {
		return "", "", err
	}
	err = c.checkOutputFile(keyFile)
	if err != nil {
		return "", "", err
	}

	data, err := os.ReadFile(c.RootCA)
	if err != nil {
		return "", "", err
	}

	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(data)
	if !ok {
		return "", "", Fatalf("failed reading rootCA: %s", c.RootCA)
	}

	cmdArgs = []string{
		"ca", "certificate",
		subjectName, certFile, keyFile,
		fmt.Sprintf("--ca-url=%s", c.CaURL),
		fmt.Sprintf("--root=%s", c.RootCA),
		fmt.Sprintf("--issuer=%s", c.Issuer),
		fmt.Sprintf("--provisioner-password-file=%s", c.PasswordFile),
	}

	notBefore := time.Now()
	var notAfter time.Time
	switch {
	case duration == "":
		lifetime, err := time.ParseDuration(c.DefaultDuration)
		if err != nil {
			return "", "", Fatal(err)
		}
		notAfter = time.Now().Add(lifetime)
	case strings.HasSuffix(duration, "y") || strings.HasSuffix(duration, "d"):
		notAfter, err = expirationDate(duration)
		if err != nil {
			return "", "", err
		}
	default:
		lifetime, err := time.ParseDuration(duration)
		if err != nil {
			return "", "", err
		}
		notAfter = time.Now().Add(lifetime)
	}
	cmdArgs = append(cmdArgs, fmt.Sprintf("--not-before=%s", notBefore.Format(time.RFC3339)))
	cmdArgs = append(cmdArgs, fmt.Sprintf("--not-after=%s", notAfter.Format(time.RFC3339)))

	switch c.KeyType {
	case KeyTypeECURVE:
		cmdArgs = append(cmdArgs, "--kty=EC")
	case KeyTypeED25519:
		cmdArgs = append(cmdArgs, "--kty=OKP")
	case KeyTypeRSA:
		cmdArgs = append(cmdArgs, "--kty=RSA")
	default:
		return "", "", fmt.Errorf("unexpected certificate type: %v", c.KeyType)
	}

	cmdArgs = append(cmdArgs, c.StepArgs...)

	_, err = c.runStep(cmdArgs...)
	if err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil

}

func (c *CertFactory) runStep(cmdArgs ...string) ([]byte, error) {

	//if c.Debug {
	//fmt.Fprintf(os.Stderr, "runStep('%s')\n", strings.Join(cmdArgs, "', '"))
	//}

	obuf := bytes.Buffer{}
	ebuf := bytes.Buffer{}

	stepCmd := exec.Command(c.StepBinary, cmdArgs...)

	if c.Raw {
		stepCmd.Stdout = os.Stdout
		stepCmd.Stderr = os.Stderr
	} else {
		stepCmd.Stdout = &obuf
		stepCmd.Stderr = &ebuf
	}

	if c.Verbose || c.Debug {
		log.Printf("spawning: '%s'\n", stepCmd.String())
	}

	stepCmd.Env = append(os.Environ(), "TERM=xterm")

	err := stepCmd.Start()
	if err != nil {
		return []byte{}, Fatal(err)
	}

	errChan := make(chan error, 2)
	exitChan := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		timer := time.NewTimer(time.Duration(c.StepTimeoutSeconds) * time.Second)
		if c.Debug {
			log.Println("timer: starting")
			defer log.Println("timer: exiting")
		}
		defer timer.Stop()
		defer wg.Done()
		for {
			select {
			case <-timer.C:
				if c.Debug {
					log.Println("timer: timer expired")
				}
				err := stepCmd.Process.Kill()
				if err != nil {
					errChan <- Fatalf("timer: failed killing timed-out step command: %v", err)
					return
				}
			case err := <-exitChan:
				if c.Debug {
					log.Printf("timer: exitChan emitted: %v\n", err)
				}
				errChan <- err
				return
			}
		}

	}()

	wg.Add(1)
	go func() {
		if c.Debug {
			log.Println("waiter: starting")
			defer log.Println("waiter: exiting")
		}
		defer wg.Done()
		var exitCode int
		if c.Debug {
			log.Println("waiter: waiting on command")
		}
		err := stepCmd.Wait()
		if c.Debug {
			log.Printf("waiter: command wait returned: %v\n", err)
		}
		if err != nil {
			switch e := err.(type) {
			case *exec.ExitError:
				exitCode = e.ExitCode()
			default:
				exitChan <- err
				return
			}
		} else {
			exitCode = stepCmd.ProcessState.ExitCode()
		}
		if exitCode != 0 {
			exitChan <- fmt.Errorf("waiter: step command exited with exit code: %d", exitCode)
			return
		}
		exitChan <- nil
	}()

	if c.Debug {
		log.Println("runStep: waiting on goprocs...")
	}
	wg.Wait()
	if c.Debug {
		log.Println("runStep: goprocs complete")
	}

	stdout := strings.TrimSpace(obuf.String())
	if (c.Verbose || c.TTY) && stdout != "" {
		fmt.Printf("%s\n", ttyFormat(stdout))
	}

	stderr := strings.TrimSpace(ebuf.String())
	if (c.Verbose || c.TTY) && stderr != "" {
		fmt.Fprintf(os.Stderr, "%s\n", ttyFormat(stderr))
	}

	if c.Debug {
		log.Println("runStep: reading errChan...")
	}
	err = nil
	for done := false; !done; {
		select {
		case e := <-errChan:
			if c.Debug {
				log.Printf("runStep: errChan emitted %v\n", e)
			}
			if e != nil {
				err = e
			}
		default:
			done = true
		}
	}
	if c.Debug {
		log.Printf("runStep: errChan drained, err=%v\n", err)
	}

	return []byte(stdout), err
}

func ttyFormat(s string) string {
	s = ansiEscapePattern.ReplaceAllString(s, "")
	return strings.TrimSpace(emojiPattern.ReplaceAllString(s, ""))
}

func expirationDate(duration string) (time.Time, error) {
	m := regexp.MustCompile(`^([0-9]+)([dy])$`).FindStringSubmatch(duration)
	if len(m) != 3 {
		return time.Time{}, fmt.Errorf("invalid duration: '%v'", duration)
	}
	days, err := strconv.Atoi(m[1])
	if err != nil {
		return time.Time{}, err
	}
	switch m[2] {
	case "d":
	case "y":
		days = days * 365
	default:
		return time.Time{}, Fatalf("unexpected duration suffix: %s", m[2])
	}
	expiration := time.Now().AddDate(0, 0, days)
	return expiration, nil
}

func (c *CertFactory) checkOutputFile(pathname string) error {
	if IsFile(pathname) {
		if c.Overwrite {
			return os.Remove(pathname)
		}
		return fmt.Errorf("file exists: %s", pathname)
	}
	return nil
}

func CertHash(pathname string) (string, error) {
	cmd := exec.Command("openssl", "x509", "-hash", "-in", pathname, "-noout")
	var obuf bytes.Buffer
	cmd.Stdout = &obuf
	err := cmd.Run()
	if err != nil {
		return "", Fatal(err)
	}
	hash := strings.TrimSpace(obuf.String())
	log.Printf("CertHash: file=%s hash=%s\n", pathname, hash)
	return hash, nil
}
