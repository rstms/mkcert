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

const Version = "0.2.11"

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
	debug              bool
	verbose            bool
	Raw                bool
	TTY                bool
	Overwrite          bool
	stepBinary         string
	DefaultDuration    string
	stepTimeoutSeconds int64
	StepArgs           []string
	keyType            KeyType
	passwordFile       string
	issuer             string
	fingerprint        string
	caURL              string
	rootCA             string
	configDir          string
}

func NewCertFactory(stepArgs *[]string) (*CertFactory, error) {
	prefix := "mkcert."
	if ProgramName() == "mkcert" {
		prefix = ""
	}
	ViperSetDefault(prefix+"timeout_seconds", 3)
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, Fatal(err)
	}
	configDir = filepath.Join(configDir, "mkcert")
	if !IsDir(configDir) {
		err := os.MkdirAll(configDir, 0700)
		if err != nil {
			return nil, Fatal(err)
		}
	}
	ViperSetDefault(prefix+"password_file", filepath.Join(configDir, "password"))

	ViperSetDefault(prefix+"default_duration", "5m")
	f := CertFactory{
		Version:            Version,
		passwordFile:       ViperGetString(prefix + "password_file"),
		debug:              ViperGetBool(prefix + "debug"),
		verbose:            ViperGetBool(prefix + "verbose"),
		Overwrite:          ViperGetBool(prefix + "overwrite"),
		Raw:                ViperGetBool(prefix + "echo_raw"),
		TTY:                ViperGetBool(prefix + "echo_tty"),
		stepBinary:         ViperGetString(prefix + "step_command"),
		stepTimeoutSeconds: ViperGetInt64(prefix + "timeout_seconds"),
		StepArgs:           []string{},
		DefaultDuration:    ViperGetString(prefix + "default_duration"),
		keyType:            KeyTypeRSA,
		issuer:             ViperGetString(prefix + "issuer"),
		caURL:              ViperGetString(prefix + "ca_url"),
		fingerprint:        ViperGetString(prefix + "fingerprint"),
		rootCA:             ViperGetString(prefix + "root_cert"),
		configDir:          configDir,
	}

	if f.stepBinary == "" || !IsFile(f.stepBinary) {
		bin, err := InstallStepBinary()
		if err != nil {
			return nil, err
		}
		f.stepBinary = bin
		ViperSet(prefix+"step_command", bin)
	}

	if f.caURL == "" || f.fingerprint == "" || f.rootCA == "" {
		keymaster := ViperGetString(prefix + "keymaster")
		var config *StepConfig
		var err error
		if keymaster != "" && IsFile(keymaster) {
			// side effect: initFromKeymaster will set issuer if a match is found
			config, err = f.initFromKeymaster(keymaster)
			if err != nil {
				return nil, err
			}
		}

		// keymaster config did not work, try reading the ~/.step config
		if config == nil {
			config, err = f.readStepConfig()
			if err != nil {
				return nil, Fatalf("failed reading step config: %v", err)
			}
		}
		if config != nil {
			if f.caURL == "" {
				f.caURL = config.URL
				ViperSet(prefix+"ca_url", f.caURL)
			}

			if f.fingerprint == "" {
				f.fingerprint = config.Fingerprint
				ViperSet(prefix+"fingerprint", f.fingerprint)
			}

			if f.rootCA == "" {
				f.rootCA = config.Root
				ViperSet(prefix+"root_cert", f.rootCA)
			}
		}
	}

	// if issuer or caURL are still unset, try setting domain-based values
	if f.issuer == "" || f.caURL == "" {
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
			if f.issuer == "" {
				f.issuer = "keymaster@" + domain
				ViperSet(prefix+"issuer", f.issuer)
			}
			if f.caURL == "" {
				f.caURL = "https://keymaster." + domain
				ViperSet(prefix+"ca_url", f.caURL)
			}
		}
	}

	if ViperGetString(prefix+"issuer") == "" && f.issuer != "" {
		ViperSet(prefix+"issuer", f.issuer)
	}

	if f.caURL == "" {
		return nil, Fatalf("missing config: ca_url")
	}

	_, err = url.Parse(f.caURL)
	if err != nil {
		return nil, Fatalf("failed parsing ca_url '%s': %v", f.caURL, err)
	}

	if f.fingerprint == "" {
		return nil, Fatalf("missing config: fingerprint")
	}

	if f.rootCA == "" {
		return nil, Fatalf("missing config: root_cert")

	}

	if f.issuer == "" {
		return nil, Fatalf("missing config: issuer")
	}

	if f.passwordFile == "" {
		return nil, Fatalf("missing config: password_file")

	}

	// add passed-in stepArgs if any
	if stepArgs != nil {
		f.StepArgs = append(f.StepArgs, *stepArgs...)
	}

	if f.debug {
		log.Printf("NewCertFactory: %+v\n", f)
	}
	return &f, nil
}

func (c *CertFactory) initFromKeymaster(keymasterFile string) (*StepConfig, error) {
	// extract the root cert from keymaster (it may be a chain)
	rootData, err := c.runStep("certificate", "inspect", "--format=pem", keymasterFile)
	if err != nil {
		return nil, Fatal(err)
	}
	var config StepConfig
	config.Root = filepath.Join(c.configDir, "root.pem")
	err = os.WriteFile(config.Root, rootData, 0600)
	if err != nil {
		return nil, Fatal(err)
	}

	// read and decode the root CA as json
	fpData, err := c.runStep("certificate", "fingerprint", config.Root)
	if err != nil {
		return nil, Fatal(err)
	}
	config.Fingerprint = string(fpData)

	keymasterConfigFile := filepath.Join(c.configDir, "keymaster.yaml")
	if !IsFile(keymasterConfigFile) {
		// create keymaster config file if not present
		err := os.WriteFile(keymasterConfigFile, []byte(defaultKeymasterConfig), 0600)
		if err != nil {
			return nil, Fatal(err)
		}
	}
	kmData, err := os.ReadFile(keymasterConfigFile)
	if err != nil {
		return nil, Fatal(err)
	}
	var keymasterConfig map[string]KeymasterConfig

	err = yaml.Unmarshal(kmData, &keymasterConfig)
	if err != nil {
		return nil, Fatalf("failed decoding: %s: %v", keymasterConfigFile, err)
	}

	kmcfg, ok := keymasterConfig[config.Fingerprint]
	if ok {
		// assemble URL from keymaster config
		var kmurl url.URL
		kmurl.Scheme = "https"
		if kmcfg.Port == 0 || kmcfg.Port == 443 {
			kmurl.Host = kmcfg.Hostname
		} else {
			kmurl.Host = fmt.Sprintf("%s:%d", kmcfg.Hostname, kmcfg.Port)
		}
		kmurl.Path = kmcfg.Path
		config.URL = kmurl.String()
		// test for valid URL
		_, err = url.Parse(config.URL)
		if err != nil {
			return nil, Fatalf("failed parsing keymaster config URL %s: %v", config.URL, err)
		}
		// side-effect: set issuer if unset
		if c.issuer == "" {
			c.issuer = kmcfg.Issuer
		}
		return &config, nil
	}
	Warning("keymaster fingerprint %s not found in %s", config.Fingerprint, keymasterConfigFile)
	return nil, nil

}

func (c *CertFactory) readStepConfig() (*StepConfig, error) {
	stdout, err := c.runStep("path")
	if err != nil {
		return nil, Fatal(err)
	}
	stepPath := string(stdout)
	if stepPath == "" || !IsDir(stepPath) {
		return nil, nil
	}
	stepConfig := filepath.Join(stepPath, "config", "defaults.json")
	data, err := os.ReadFile(stepConfig)
	if err != nil {
		return nil, Fatal(err)
	}
	var config StepConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, Fatalf("failed parsing step config: %v", err)
	}
	return &config, nil
}

func (c *CertFactory) SetKeyType(keyType KeyType) {
	c.keyType = keyType
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
		"--ca-url", c.caURL,
		"--fingerprint", c.fingerprint,
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

	data, err := os.ReadFile(c.rootCA)
	if err != nil {
		return "", "", err
	}

	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(data)
	if !ok {
		return "", "", Fatalf("failed reading rootCA: %s", c.rootCA)
	}

	cmdArgs = []string{
		"ca", "certificate",
		subjectName, certFile, keyFile,
		fmt.Sprintf("--ca-url=%s", c.caURL),
		fmt.Sprintf("--root=%s", c.rootCA),
		fmt.Sprintf("--issuer=%s", c.issuer),
		fmt.Sprintf("--provisioner-password-file=%s", c.passwordFile),
	}
	/*
		fmt.Sprintf("--fingerprint=%s", c.fingerprint),
	*/

	switch {
	case duration == "":
	case strings.HasSuffix(duration, "y") || strings.HasSuffix(duration, "d"):
		d, err := expirationDate(duration)
		if err != nil {
			return "", "", err
		}
		duration = d
	default:
		d, err := time.ParseDuration(duration)
		if err != nil {
			return "", "", err
		}
		duration = d.String()
	}
	if duration != "" {
		cmdArgs = append(cmdArgs, fmt.Sprintf("--not-after=%s", duration))
	}

	switch c.keyType {
	case KeyTypeECURVE:
		cmdArgs = append(cmdArgs, "--kty=EC")
	case KeyTypeED25519:
		cmdArgs = append(cmdArgs, "--kty=OKP")
	case KeyTypeRSA:
		cmdArgs = append(cmdArgs, "--kty=RSA")
	default:
		return "", "", fmt.Errorf("unexpected certificate type: %v", c.keyType)
	}

	cmdArgs = append(cmdArgs, c.StepArgs...)

	_, err = c.runStep(cmdArgs...)
	if err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil

}

func (c *CertFactory) runStep(cmdArgs ...string) ([]byte, error) {

	//if c.debug {
	//fmt.Fprintf(os.Stderr, "runStep('%s')\n", strings.Join(cmdArgs, "', '"))
	//}

	obuf := bytes.Buffer{}
	ebuf := bytes.Buffer{}

	stepCmd := exec.Command(c.stepBinary, cmdArgs...)

	if c.Raw {
		stepCmd.Stdout = os.Stdout
		stepCmd.Stderr = os.Stderr
	} else {
		stepCmd.Stdout = &obuf
		stepCmd.Stderr = &ebuf
	}

	if c.verbose || c.debug {
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
		timer := time.NewTimer(time.Duration(c.stepTimeoutSeconds) * time.Second)
		if c.debug {
			log.Println("timer: starting")
			defer log.Println("timer: exiting")
		}
		defer timer.Stop()
		defer wg.Done()
		for {
			select {
			case <-timer.C:
				if c.debug {
					log.Println("timer: timer expired")
				}
				err := stepCmd.Process.Kill()
				if err != nil {
					errChan <- Fatalf("timer: failed killing timed-out step command: %v", err)
					return
				}
			case err := <-exitChan:
				if c.debug {
					log.Printf("timer: exitChan emitted: %v\n", err)
				}
				errChan <- err
				return
			}
		}

	}()

	wg.Add(1)
	go func() {
		if c.debug {
			log.Println("waiter: starting")
			defer log.Println("waiter: exiting")
		}
		defer wg.Done()
		var exitCode int
		if c.debug {
			log.Println("waiter: waiting on command")
		}
		err := stepCmd.Wait()
		if c.debug {
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

	if c.debug {
		log.Println("runStep: waiting on goprocs...")
	}
	wg.Wait()
	if c.debug {
		log.Println("runStep: goprocs complete")
	}

	stdout := strings.TrimSpace(obuf.String())
	if (c.verbose || c.TTY) && stdout != "" {
		fmt.Printf("%s\n", ttyFormat(stdout))
	}

	stderr := strings.TrimSpace(ebuf.String())
	if (c.verbose || c.TTY) && stderr != "" {
		fmt.Fprintf(os.Stderr, "%s\n", ttyFormat(stderr))
	}

	if c.debug {
		log.Println("runStep: reading errChan...")
	}
	err = nil
	for done := false; !done; {
		select {
		case e := <-errChan:
			if c.debug {
				log.Printf("runStep: errChan emitted %v\n", e)
			}
			if e != nil {
				err = e
			}
		default:
			done = true
		}
	}
	if c.debug {
		log.Printf("runStep: errChan drained, err=%v\n", err)
	}

	return []byte(stdout), err
}

func ttyFormat(s string) string {
	s = ansiEscapePattern.ReplaceAllString(s, "")
	return strings.TrimSpace(emojiPattern.ReplaceAllString(s, ""))
}

func expirationDate(duration string) (string, error) {
	if len(duration) == 0 {
		return "", fmt.Errorf("invalid duration: '%v'", duration)
	}
	unit := string([]rune(duration)[len(duration)-1])
	duration = string([]rune(duration)[:len(duration)-1])
	days, err := strconv.Atoi(duration)
	if err != nil {
		return "", err
	}
	if unit == "y" {
		days = days * 365
	}
	now := time.Now()
	expiration := now.AddDate(0, 0, days)
	return expiration.Format(time.RFC3339), nil
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
