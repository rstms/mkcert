package factory

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
)

//go:embed bin/windows_step.exe
var winStep []byte

//go:embed bin/linux_step
var linuxStep []byte

//go:embed bin/openbsd_step
var openbsdStep []byte

func InstallStepBinary() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", Fatal(err)
	}
	var stepData []byte
	stepName := "step"
	switch runtime.GOOS {
	case "linux":
		stepData = linuxStep
	case "openbsd":
		stepData = openbsdStep
	case "windows":
		stepData = winStep
		stepName = "step.exe"
	default:
		return "", Fatalf("unsupported OS: %s", runtime.GOOS)
	}
	stepDir := filepath.Join(cacheDir, "mkcert")
	err = os.MkdirAll(stepDir, 0700)
	if err != nil {
		return "", Fatal(err)
	}
	stepBin := filepath.Join(stepDir, stepName)
	err = os.WriteFile(stepBin, stepData, 0700)
	if err != nil {
		return "", Fatal(err)
	}
	return stepBin, nil
}
