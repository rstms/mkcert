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
package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	DEFAULT_ISSUER        = "keymaster@rstms.net"
	DEFAULT_PASSWORD_FILE = "~/.secrets/.keymaster_password"
)

var cfgFile string
var verbose bool
var issuer string
var passwordFile string
var certFile string
var keyFile string
var duration string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mkcert [flags] SUBJECT [-- STEP-OPTS]",
	Short: "make client certificate",
	Long: `
Create a client certificate signed by the Reliance Systems Keymaster CA
`,
	Args: cobra.MinimumNArgs(1),
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		subjectName := args[0]
		stepArgs := args[1:]
		passwordFile, err := resolveTildePath(passwordFile)
		cobra.CheckErr(err)
		if certFile == "" {
			certFile = fmt.Sprintf("%s.pem", subjectName)
		}
		if keyFile == "" {
			keyFile = fmt.Sprintf("%s.key", subjectName)
		}
		cmdArgs := []string{"ca", "certificate", subjectName, certFile, keyFile}
		cmdArgs = append(cmdArgs, fmt.Sprintf("--issuer=%s", issuer))
		cmdArgs = append(cmdArgs, fmt.Sprintf("--provisioner-password-file=%s", passwordFile))

		switch {
		case duration == "":
		case strings.HasSuffix(duration, "y") || strings.HasSuffix(duration, "d"):
			d, err := expirationDate(duration)
			cobra.CheckErr(err)
			duration = d
		default:
			d, err := time.ParseDuration(duration)
			cobra.CheckErr(err)
			duration = d.String()
		}
		if duration != "" {
			cmdArgs = append(cmdArgs, fmt.Sprintf("--not-after=%s", duration))
		}
		cmdArgs = append(cmdArgs, stepArgs...)
		if verbose {
			fmt.Fprintf(os.Stderr, "%s %s\n", "step", strings.Join(cmdArgs, " "))
		}
		stepCmd := exec.Command("step", cmdArgs...)
		stepCmd.Stdout = os.Stdout
		stepCmd.Stderr = os.Stderr
		err = stepCmd.Run()
		cobra.CheckErr(err)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.mkcert.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print step command line to stderr before executing")
	rootCmd.Flags().StringVarP(&issuer, "issuer", "i", DEFAULT_ISSUER, "issuer/provisioner")
	rootCmd.Flags().StringVarP(&passwordFile, "password-file", "p", DEFAULT_PASSWORD_FILE, "provisioner password file")
	rootCmd.Flags().StringVarP(&duration, "duration", "d", "", "duration to expiration: valid units are: ns,us,ms,s,m,h,d,y")
	rootCmd.Flags().StringVarP(&certFile, "cert-file", "c", "", "new certificate filename")
	rootCmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "new key filename")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".mkcert" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".mkcert")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func resolveTildePath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = strings.Replace(path, "~", homeDir, 1)
	}
	return filepath.Clean(path), nil
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
