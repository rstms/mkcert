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
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Version: "0.1.6",
	Use:     "mkcert [flags] SUBJECT [-- STEP-OPTS]",
	Short:   "make client certificate",
	Long: `
Create a client certificate signed by the Reliance Systems Keymaster CA
The --rootCA flag writes the root CA cert to a file named by SUBJECT.
`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		viper.Set("mkcert.verbose", viper.GetBool("verbose"))
		viper.Set("mkcert.debug", viper.GetBool("debug"))
		viper.Set("mkcert.overwrite", viper.GetBool("force"))
		if viper.GetBool("tty") {
			viper.Set("mkcert.echo_tty", true)
		}
		if viper.GetBool("emoji") {
			viper.Set("mkcert.echo_raw", true)
		}
		issuer := viper.GetString("issuer")
		if issuer != "" {
			viper.Set("mkcert.issuer", issuer)
		}
		passwordFile := viper.GetString("password_file")
		if passwordFile != "" {
			viper.Set("mkcert.password_file", passwordFile)
		}

		subject := args[0]
		optArgs := []string{}
		if len(args) > 1 {
			optArgs = args[1:]
		}
		certFactory, err := factory.NewCertFactory(&optArgs)

		switch {
		case viper.GetBool("ecurve"):
			certFactory.SetKeyType(factory.KeyTypeECURVE)
		case viper.GetBool("ed25519"):
			certFactory.SetKeyType(factory.KeyTypeED25519)
		}

		outputCertFile := viper.GetString("cert_file")
		outputKeyFile := viper.GetString("key_file")

		cobra.CheckErr(err)
		switch {
		case viper.GetBool("root"):
			certFile, err := certFactory.Root(subject)
			cobra.CheckErr(err)
			fmt.Println(certFile)
		case viper.GetBool("chain"):
			certFile, err := certFactory.Chain(subject)
			cobra.CheckErr(err)
			fmt.Println(certFile)
		default:
			duration := viper.GetString("duration")
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
	cobra.OnInitialize(InitConfig)
	OptionString("logfile", "l", "", "log filename")
	OptionString("config", "c", "", "config file")
	OptionSwitch("debug", "", "produce debug output")
	OptionSwitch("verbose", "", "increase verbosity")
	OptionSwitch("force", "", "overwrite existing files")
	OptionSwitch("root", "", "generate root CA cert")
	OptionSwitch("chain", "", "generate root/intermeiate CA cert chain")
	OptionSwitch("emoji", "", "don't strip emoji and ANSI codes from output")
	OptionSwitch("tty", "", "show tty output from 'step' command")

	OptionString("issuer", "", "", "issuer/provisioner")
	OptionString("password-file", "", "", "provisioner password file")
	OptionString("duration", "d", "5m", "duration to expiration: valid units are: ns,us,ms,s,m,h,d,y")
	OptionString("cert-file", "", "", "certificate output filename")
	OptionString("key-file", "", "", "key output filename")

	OptionSwitch("rsa", "", "RSA key type (default)")
	OptionSwitch("ecurve", "", "Elliptic Curve key type")
	OptionSwitch("ed25519", "", "ed25519 key type")

	rootCmd.MarkFlagsMutuallyExclusive("rsa", "ecurve")
	rootCmd.MarkFlagsMutuallyExclusive("rsa", "ed25519")
	rootCmd.MarkFlagsMutuallyExclusive("ecurve", "ed25519")
}
