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
	"fmt"
	"github.com/spf13/viper"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const VERSION = "0.0.9"

var EmojiPattern = regexp.MustCompile(`(?:[` +
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

var ANSIEscapePattern = regexp.MustCompile(`\x1B\[[;?0-9]*[mK]`)

type KeyType int

const (
	KeyTypeRSA = iota
	KeyTypeECURVE
	KeyTypeED25519
)

type CertFactory struct {
	Version            string
	debug              bool
	raw                bool
	tty                bool
	overwrite          bool
	stepBinary         string
	stepTimeoutSeconds int64
	stepArgs           []string
	keyType            KeyType
	passwordFile       string
	issuer             string
	DefaultDuration    string
}

func NewCertFactory(stepArgs *[]string) (*CertFactory, error) {
	viper.SetDefault("mkcert.step.command", "step")
	viper.SetDefault("mkcert.step.timeout_seconds", 3)
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	viper.SetDefault("mkcert.password_file", filepath.Join(configDir, "mkcert", "password"))
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	domain := hostname
	host, domain, ok := strings.Cut(hostname, ".")
	if !ok {
		domain = host
	}
	viper.SetDefault("mkcert.issuer", "keymaster@"+domain)
	viper.SetDefault("mkcert.default_duration", "5m")
	f := CertFactory{
		Version:            VERSION,
		debug:              viper.GetBool("mkcert.debug"),
		overwrite:          viper.GetBool("mkcert.overwrite"),
		raw:                viper.GetBool("mkcert.echo_raw"),
		tty:                viper.GetBool("mkcert.echo_tty"),
		stepBinary:         viper.GetString("mkcert.step.command"),
		stepTimeoutSeconds: viper.GetInt64("mkcert.step.timeout_seconds"),
		stepArgs:           *stepArgs,
		DefaultDuration:    viper.GetString("mkcert.default_duration"),
		keyType:            KeyTypeRSA,
		issuer:             viper.GetString("mkcert.issuer"),
	}
	p, err := resolveTildePath(viper.GetString("mkcert.password_file"))
	if err != nil {
		return nil, err
	}
	f.passwordFile = p
	if f.debug {
		log.Printf("NewCertFactory: %+v\n", f)
	}
	return &f, nil
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

	args := []string{"ca", "root", "-f", certFile}
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
	fmt.Printf("cert=%s key=%s\n", certFile, keyFile)
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

	cmdArgs = []string{"ca", "certificate", subjectName, certFile, keyFile}
	cmdArgs = append(cmdArgs, fmt.Sprintf("--issuer=%s", c.issuer))
	cmdArgs = append(cmdArgs, fmt.Sprintf("--provisioner-password-file=%s", c.passwordFile))

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

	cmdArgs = append(cmdArgs, c.stepArgs...)

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

	if c.raw {
		stepCmd.Stdout = os.Stdout
		stepCmd.Stderr = os.Stderr
	} else if c.tty {
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

	if c.tty {
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
	s = ANSIEscapePattern.ReplaceAllString(s, "")
	return EmojiPattern.ReplaceAllString(s, "")
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
	fmt.Printf("days=%d unit=%s\n", days, unit)
	expiration := now.AddDate(0, 0, days)
	return expiration.Format(time.RFC3339), nil
}

func (c *CertFactory) checkOutputFile(pathname string) error {
	if IsFile(pathname) {
		if c.overwrite {
			return os.Remove(pathname)
		}
		return fmt.Errorf("file exists: %s", pathname)
	}
	return nil
}

func IsFile(pathname string) bool {
	_, err := os.Stat(pathname)
	return !os.IsNotExist(err)
}
