// go-common local proxy functions

package cmd

import (
	common "github.com/rstms/go-common"
)

type APIClient interface {
	Close()
	Get(path string, response interface{}) (string, error)
	Post(path string, request, response interface{}, headers *map[string]string) (string, error)
	Put(path string, request, response interface{}, headers *map[string]string) (string, error)
	Delete(path string, response interface{}) (string, error)
}

type CobraCommand interface {
}

type Sendmail interface {
	Send(to, from, subject string, body []byte) error
}

func NewAPIClient(prefix, url, certFile, keyFile, caFile string, headers *map[string]string) (APIClient, error) {
	return common.NewAPIClient(prefix, url, certFile, keyFile, caFile, headers)
}

func OptionKey(cobraCmd CobraCommand, key string) string {
	return common.OptionKey(cobraCmd, key)
}

func OptionSwitch(cobraCmd CobraCommand, name, flag, description string) {
	common.OptionSwitch(cobraCmd, name, flag, description)
}

func OptionString(cobraCmd CobraCommand, name, flag, defaultValue, description string) {
	common.OptionString(cobraCmd, name, flag, defaultValue, description)
}

func OptionInt(cobraCmd CobraCommand, name, flag string, defaultValue int, description string) {
	common.OptionInt(cobraCmd, name, flag, defaultValue, description)
}

func CobraAddCommand(cobraRootCmd, parentCmd, cobraCmd CobraCommand) {
	common.CobraAddCommand(cobraRootCmd, parentCmd, cobraCmd)
}

func CobraInit(cobraRootCmd CobraCommand) {
	common.CobraInit(cobraRootCmd)
}

func Init(name, version, configFile string) {
	common.Init(name, version, configFile)
}

func Shutdown() {
	common.Shutdown()
}

func ProgramName() string {
	return common.ProgramName()
}

func ProgramVersion() string {
	return common.ProgramVersion()
}

func ConfigDir() string {
	return common.ConfigDir()
}

func CheckErr(err error) {
	common.CheckErr(err)
}

func FormatJSON(v any) string {
	return common.FormatJSON(v)
}

func ConfigString(header bool) string {
	return common.ConfigString(header)
}

func FormatYAML(value any) string {
	return common.FormatYAML(value)
}

func ConfigInit(allowClobber bool) string {
	return common.ConfigInit(allowClobber)
}

func ConfigEdit() {
	common.ConfigEdit()
}

func Confirm(prompt string) bool {
	return common.Confirm(prompt)
}

func Fatal(err error) error {
	return common.Fatal(err)
}

func Fatalf(format string, args ...interface{}) error {
	return common.Fatalf(format, args...)
}

func Warning(format string, args ...interface{}) {
	common.Warning(format, args...)
}

func HexDump(data []byte) string {
	return common.HexDump(data)
}

func IsDir(path string) bool {
	return common.IsDir(path)
}

func IsFile(pathname string) bool {
	return common.IsFile(pathname)
}

func TildePath(path string) (string, error) {
	return common.TildePath(path)
}

func NewSendmail(hostname string, port int, username, password, CAFile string) (Sendmail, error) {
	return common.NewSendmail(hostname, port, username, password, CAFile)
}

func Expand(value string) string {
	return common.Expand(value)
}

func ViperKey(key string) string {
	return common.ViperKey(key)
}

func ViperGet(key string) any {
	return common.ViperGet(key)
}

func ViperGetBool(key string) bool {
	return common.ViperGetBool(key)
}

func ViperGetString(key string) string {
	return common.ViperGetString(key)
}

func ViperGetStringSlice(key string) []string {
	return common.ViperGetStringSlice(key)
}

func ViperGetStringMapString(key string) map[string]string {
	return common.ViperGetStringMapString(key)
}

func ViperGetInt(key string) int {
	return common.ViperGetInt(key)
}

func ViperGetInt64(key string) int64 {
	return common.ViperGetInt64(key)
}

func ViperSet(key string, value any) {
	common.ViperSet(key, value)
}

func ViperSetDefault(key string, value any) {
	common.ViperSetDefault(key, value)
}
