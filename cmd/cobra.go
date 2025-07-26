package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var ViperPrefix = ""
var LogFile *os.File

func ViperKey(name string) string {
	return ViperPrefix + strings.ReplaceAll(name, "-", "_")
}

func OptionSwitch(name, flag, description string) {

	if flag == "" {
		rootCmd.PersistentFlags().Bool(name, false, description)
	} else {
		rootCmd.PersistentFlags().BoolP(name, flag, false, description)
	}

	viper.BindPFlag(ViperKey(name), rootCmd.PersistentFlags().Lookup(name))
}

func OptionString(name, flag, defaultValue, description string) {

	if flag == "" {
		rootCmd.PersistentFlags().String(name, defaultValue, description)
	} else {
		rootCmd.PersistentFlags().StringP(name, flag, defaultValue, description)
	}

	viper.BindPFlag(ViperKey(name), rootCmd.PersistentFlags().Lookup(name))
}

func OpenLog() {
	filename := viper.GetString("logfile")
	LogFile = nil
	if filename == "stdout" || filename == "-" {
		log.SetOutput(os.Stdout)
	} else if filename == "stderr" || filename == "" {
		log.SetOutput(os.Stderr)
	} else {
		fp, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err != nil {
			log.Fatalf("failed opening log file: %v", err)
		}
		LogFile = fp
		log.SetOutput(LogFile)
		log.SetPrefix(fmt.Sprintf("[%d] ", os.Getpid()))
		log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
		log.Printf("%s v%s startup\n", rootCmd.Name(), rootCmd.Version)
		cobra.OnFinalize(CloseLog)
	}
	if viper.GetBool("debug") {
		log.SetFlags(log.Flags() | log.Lshortfile)
	}
}

func CloseLog() {
	if LogFile != nil {
		log.Println("shutdown")
		err := LogFile.Close()
		cobra.CheckErr(err)
		LogFile = nil
	}
}

func FormatJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("failed formatting JSON: %v", err)
	}
	return string(data)
}

func IsDir(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return stat.IsDir()
}

func IsFile(pathname string) bool {
	_, err := os.Stat(pathname)
	return !os.IsNotExist(err)
}

func ExpandPath(pathname string) string {
	if len(pathname) > 1 && pathname[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("failed getting user home dir: %v", err)
		}
		pathname = filepath.Join(home, pathname[1:])
	}
	return pathname
}

func InitConfig() {
	viper.SetEnvPrefix(strings.ToLower(rootCmd.Name()))
	viper.AutomaticEnv()
	filename := viper.GetString("config")
	if filename != "" {
		viper.SetConfigFile(filename)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		userConfig, err := os.UserConfigDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(filepath.Join(home, "."+rootCmd.Name()))
		viper.AddConfigPath(filepath.Join(userConfig, rootCmd.Name()))
		viper.AddConfigPath(filepath.Join("/etc", rootCmd.Name()))
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}
	err := viper.ReadInConfig()
	if err != nil {
		_, ok := err.(viper.ConfigFileNotFoundError)
		if !ok {
			cobra.CheckErr(err)
		}
	}
	OpenLog()
	if viper.ConfigFileUsed() != "" && viper.GetBool("debug") {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}
}
