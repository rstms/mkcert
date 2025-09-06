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
	"encoding/json"
	"fmt"
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

const Version = "0.2.8"

var DEFAULT_URL_SUBJECT_MAP map[string]string = map[string]string{
	"https://keymaster.rstms.net": "CN=Reliance Systems Keymaster Root CA",
}

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

type KeyType int

const (
	KeyTypeRSA = iota
	KeyTypeECURVE
	KeyTypeED25519
)

type CertFactory struct {
	Version            string
	debug              bool
	Raw                bool
	TTY                bool
	Overwrite          bool
	stepBinary         string
	stepTimeoutSeconds int64
	StepArgs           []string
	keyType            KeyType
	passwordFile       string
	issuer             string
	DefaultDuration    string
	fingerprint        string
	caURL              string
	rootCA             string
	keymaster          string
	URLSubjectMap      map[string]string
}

func NewCertFactory(stepArgs *[]string) (*CertFactory, error) {
	prefix := "mkcert."
	if ProgramName() == "mkcert" {
		prefix = ""
	}
	ViperSetDefault(prefix+"timeout_seconds", 3)
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	ViperSetDefault(prefix+"password_file", filepath.Join(configDir, "mkcert", "password"))
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	domain := hostname
	host, domain, ok := strings.Cut(hostname, ".")
	if !ok {
		domain = host
	}
	ViperSetDefault(prefix+"issuer", "keymaster@"+domain)
	ViperSetDefault(prefix+"default_duration", "5m")
	ViperSetDefault(prefix+"url_subject_map", DEFAULT_URL_SUBJECT_MAP)
	f := CertFactory{
		Version:            Version,
		keymaster:          ViperGetString(prefix + "keymaster"),
		passwordFile:       ViperGetString(prefix + "password_file"),
		debug:              ViperGetBool(prefix + "debug"),
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
		URLSubjectMap:      ViperGetStringMapString(prefix + "url_subject_map"),
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

		var config *StepConfig
		var err error
		switch {
		case IsFile(f.keymaster):
			config, err = f.initFromKeymaster()
			if err != nil {
				return nil, err
			}
		default:
			config, err = f.readStepConfig()
			if err != nil {
				return nil, Fatalf("failed reading step config: %v", err)
			}
		}

		if f.caURL == "" {
			if config == nil {
				return nil, Fatalf("missing ca_url")
			}
			f.caURL = config.URL
		}
		ViperSet(prefix+"ca_url", f.caURL)

		if f.fingerprint == "" {
			if config == nil {
				return nil, Fatalf("missing fingerprint")
			}
			f.fingerprint = config.Fingerprint
		}
		ViperSet(prefix+"fingerprint", f.fingerprint)

		if f.rootCA == "" {
			if config == nil {
				return nil, Fatalf("missing root_cert")
			}
			f.rootCA = config.Root
		}
		ViperSet(prefix+"root_cert", f.rootCA)
	}

	_, err = url.Parse(f.caURL)
	if err != nil {
		return nil, Fatalf("failed parsing ca_url '%s': %v", f.caURL, err)
	}

	if f.fingerprint == "" {
		return nil, Fatalf("no fingerprint configured")
	}

	if stepArgs != nil {
		f.StepArgs = append(f.StepArgs, *stepArgs...)
	}

	if f.debug {
		log.Printf("NewCertFactory: %+v\n", f)
	}
	return &f, nil
}

func (c *CertFactory) initFromKeymaster() (*StepConfig, error) {
	var config StepConfig
	cmd := exec.Command(c.stepBinary, "certificate", "inspect", "--format=pem", c.keymaster)
	var rootData bytes.Buffer
	var rootErr bytes.Buffer
	cmd.Stdout = &rootData
	cmd.Stderr = &rootErr
	err := cmd.Run()
	if err != nil {
		log.Printf("command '%s' failed: %s\n", cmd.String(), rootErr.String())
		return nil, Fatalf("failed inspecting keymaster cert '%s' :%v", c.keymaster, err)
	}
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return nil, Fatal(err)
	}
	configDir := filepath.Join(userConfigDir, "mkcert")
	err = os.MkdirAll(configDir, 0700)
	if err != nil {
		return nil, Fatal(err)
	}
	config.Root = filepath.Join(configDir, "root.pem")
	err = os.WriteFile(config.Root, rootData.Bytes(), 0600)
	if err != nil {
		return nil, Fatal(err)
	}

	cmd = exec.Command(c.stepBinary, "certificate", "inspect", "--format=json", config.Root)
	var fpData bytes.Buffer
	var fpErr bytes.Buffer
	cmd.Stdout = &fpData
	cmd.Stderr = &fpErr
	err = cmd.Run()
	if err != nil {
		log.Printf("command '%s' failed: %s\n", cmd.String(), fpErr.String())
		return nil, Fatalf("failed reading root '%s' fingerprint :%v", config.Root, err)
	}
	var rootCA map[string]any
	err = json.Unmarshal(fpData.Bytes(), &rootCA)
	if err != nil {
		return nil, Fatalf("failed decoding root CA: %v", err)
	}
	config.Fingerprint = rootCA["fingerprint_sha256"].(string)

	// if we recognize the root subject, set the URL
	for url, subject := range c.URLSubjectMap {
		if rootCA["subject_dn"] == subject {
			config.URL = url
			break
		}
	}

	return &config, nil
}

func (c *CertFactory) readStepConfig() (*StepConfig, error) {
	command := exec.Command(c.stepBinary, "path")
	var stdout bytes.Buffer
	command.Stdout = &stdout
	err := command.Run()
	if err != nil {
		return nil, err
	}
	stepPath := strings.TrimSpace(stdout.String())
	if !IsDir(stepPath) {
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
		"ca",
		"root",
		"--force",
		fmt.Sprintf("--ca-url=%s", c.caURL),
		fmt.Sprintf("--fingerprint=%s", c.fingerprint),
		certFile,
	}
	err = c.runStep(args)
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

	cmdArgs = []string{"ca", "certificate", subjectName, certFile, keyFile}
	cmdArgs = append(cmdArgs, fmt.Sprintf("--ca-url=%s", c.caURL))
	cmdArgs = append(cmdArgs, fmt.Sprintf("--root=%s", c.rootCA))
	cmdArgs = append(cmdArgs, fmt.Sprintf("--issuer=%s", c.issuer))
	cmdArgs = append(cmdArgs, fmt.Sprintf("--provisioner-password-file=%s", c.passwordFile))
	cmdArgs = append(cmdArgs, fmt.Sprintf("--ca-url=%s", c.caURL))

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

	var typeOption string
	switch c.keyType {
	case KeyTypeECURVE:
		typeOption = "--kty=EC"
	case KeyTypeED25519:
		typeOption = "--kty=OKP"
	case KeyTypeRSA:
		typeOption = "--kty=RSA"
	default:
		return "", "", fmt.Errorf("unexpected certificate type: %v", c.keyType)
	}

	cmdArgs = append(cmdArgs, typeOption)

	cmdArgs = append(cmdArgs, c.StepArgs...)

	err = c.runStep(cmdArgs)
	if err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil

}

func (c *CertFactory) runStep(cmdArgs []string) error {

	if c.debug {
		fmt.Fprintf(os.Stderr, "%s %s\n", c.stepBinary, strings.Join(cmdArgs, " "))
	}

	obuf := bytes.Buffer{}
	ebuf := bytes.Buffer{}

	stepCmd := exec.Command(c.stepBinary, cmdArgs...)

	if c.Raw {
		stepCmd.Stdout = os.Stdout
		stepCmd.Stderr = os.Stderr
	} else if c.TTY {
		stepCmd.Stdout = &obuf
		stepCmd.Stderr = &ebuf
	} else {
		stepCmd.Stdout = nil
		stepCmd.Stderr = nil
	}

	err := stepCmd.Start()
	if err != nil {
		return err
	}

	errChan := make(chan error, 1)
	exitChan := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		timer := time.NewTimer(time.Duration(c.stepTimeoutSeconds) * time.Second)
		if c.debug {
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
					log.Fatalf("failed killing timed-out step command: %v", err)
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
			defer log.Println("waiter: exiting")
		}
		defer wg.Done()
		var exitCode int
		if c.debug {
			log.Println("waiting for step command")
		}
		err := stepCmd.Wait()
		if c.debug {
			log.Printf("step command wait returned: %v\n", err)
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
			exitChan <- fmt.Errorf("step command exited with exit code: %d", exitCode)
			return
		}
		exitChan <- nil
	}()

	if c.debug {
		log.Println("waiting on goprocs")
	}
	wg.Wait()
	if c.debug {
		log.Println("goprocs complete")
	}

	if c.TTY {
		if obuf.Len() > 0 {
			fmt.Print(ttyFormat(obuf.String()))
		}
		if ebuf.Len() > 0 {
			fmt.Fprint(os.Stderr, ttyFormat(ebuf.String()))
		}
	}

	if c.debug {
		log.Println("runStep: reading errChan")
	}
	err = <-errChan
	if c.debug {
		log.Printf("runStep: returning %v\n", err)
	}
	return err
}

func ttyFormat(s string) string {
	s = ansiEscapePattern.ReplaceAllString(s, "")
	return emojiPattern.ReplaceAllString(s, "")
}

func resolveTildePath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = strings.Replace(path, "~", homeDir, 1)
	}
	path = filepath.Clean(path)
	_, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return path, nil
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
