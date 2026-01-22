//go:build !windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
)

func RunAsService(run func() error) error {
	return run()
}

func InstallService() error {
	return fmt.Errorf("service installation not supported on this platform")
}

func UninstallService() error {
	return fmt.Errorf("service uninstallation not supported on this platform")
}

func StartService() error {
	return fmt.Errorf("service control not supported on this platform")
}

func StopService() error {
	return fmt.Errorf("service control not supported on this platform")
}

func GetWorkDir() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}
