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

func (c *CertFactory) installStepBinary() (string, error) {
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
	stepBin := filepath.Join(c.CacheDir, stepName)
	err := os.WriteFile(stepBin, stepData, 0700)
	if err != nil {
		return "", Fatal(err)
	}
	return stepBin, nil
}
