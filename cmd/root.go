/*
Copyright © 2025 Matt Krueger <mkrueger@rstms.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/rstms/mkcert/factory"
	"github.com/spf13/cobra"
)

var cfgFile string
var certFactory *factory.CertFactory

var rootCmd = &cobra.Command{
	Version: "0.2.13",
	Use:     "mkcert [flags] SUBJECT [-- STEP-OPTS]",
	Short:   "make client certificate",
	Long: `
Create a client certificate signed by the Reliance Systems Keymaster CA
The --rootCA flag writes the root CA cert to a file named by SUBJECT.
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		f, err := factory.NewCertFactory(nil)
		cobra.CheckErr(err)
		certFactory = f

	},
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		// write factory config keys from option flags
		certFactory.Overwrite = ViperGetBool("force")
		certFactory.TTY = ViperGetBool("tty")
		certFactory.Raw = ViperGetBool("emoji")

		subject := args[0]

		// write args following '--' to certFactory for pass-through to step command
		optArgs := []string{}
		if len(args) > 1 {
			optArgs = args[1:]
		}
		certFactory.StepArgs = optArgs

		switch {
		case ViperGetBool("ecurve"):
			certFactory.SetKeyType(factory.KeyTypeECURVE)
		case ViperGetBool("ed25519"):
			certFactory.SetKeyType(factory.KeyTypeED25519)
		}

		outputCertFile := ViperGetString("cert_file")
		outputKeyFile := ViperGetString("key_file")

		switch {
		case ViperGetBool("root"):
			certFile, err := certFactory.Root(subject)
			cobra.CheckErr(err)
			fmt.Println(certFile)
		case ViperGetBool("chain"):
			certFile, err := certFactory.Chain(subject)
			cobra.CheckErr(err)
			fmt.Println(certFile)
		case ViperGetBool("intermediate"):
			certFile, err := certFactory.Intermediate(subject)
			cobra.CheckErr(err)
			fmt.Println(certFile)
		case ViperGetBool("hash"):
			hash, err := factory.CertHash(subject)
			cobra.CheckErr(err)
			fmt.Println(hash)
		default:
			duration := ViperGetString("duration")
			certFile, keyFile, err := certFactory.CertificatePair(subject, duration, outputCertFile, outputKeyFile)
			cobra.CheckErr(err)
			fmt.Println(certFile)
			fmt.Println(keyFile)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
func init() {
	CobraInit(rootCmd)
	OptionSwitch(rootCmd, "force", "", "overwrite existing files")
	OptionSwitch(rootCmd, "root", "", "generate root CA cert")
	OptionSwitch(rootCmd, "hash", "", "output openssl x509 subject hash")
	OptionSwitch(rootCmd, "chain", "", "generate root/intermediate CA cert chain")
	OptionSwitch(rootCmd, "intermediate", "", "generate intermediate CA cert")
	OptionSwitch(rootCmd, "emoji", "", "don't strip emoji and ANSI codes from output")
	OptionSwitch(rootCmd, "tty", "", "show tty output from 'step' command")

	OptionString(rootCmd, "keymaster", "", "", "configuration root CA")
	OptionString(rootCmd, "password-file", "", "", "provisioner password file")
	OptionString(rootCmd, "issuer", "", "", "issuer/provisioner")

	OptionString(rootCmd, "duration", "D", "5m", "duration to expiration: valid units are: ns,us,ms,s,m,h,d,y")
	OptionString(rootCmd, "cert-file", "", "", "certificate output filename")
	OptionString(rootCmd, "key-file", "", "", "key output filename")

	OptionSwitch(rootCmd, "rsa", "", "RSA key type (default)")
	OptionSwitch(rootCmd, "ecurve", "", "Elliptic Curve key type")
	OptionSwitch(rootCmd, "ed25519", "", "ed25519 key type")

	rootCmd.MarkFlagsMutuallyExclusive("rsa", "ecurve")
	rootCmd.MarkFlagsMutuallyExclusive("rsa", "ed25519")
	rootCmd.MarkFlagsMutuallyExclusive("ecurve", "ed25519")
}
