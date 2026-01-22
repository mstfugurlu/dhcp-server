//go:build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "DHCPServer"
const serviceDesc = "DHCP Server Service"

type dhcpService struct {
	stop chan struct{}
	run  func() error
}

func (s *dhcpService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	go func() {
		s.run()
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(s.stop)
				return
			}
		}
	}
}

func RunAsService(run func() error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	if !isService {
		return run()
	}

	elog, err := eventlog.Open(serviceName)
	if err != nil {
		return err
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("%s starting", serviceName))

	s := &dhcpService{
		stop: make(chan struct{}),
		run:  run,
	}

	err = svc.Run(serviceName, s)
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s failed: %v", serviceName, err))
		return err
	}

	elog.Info(1, fmt.Sprintf("%s stopped", serviceName))
	return nil
}

func InstallService() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	config := mgr.Config{
		DisplayName: serviceName,
		Description: serviceDesc,
		StartType:   mgr.StartAutomatic,
	}

	s, err = m.CreateService(serviceName, exePath, config)
	if err != nil {
		return err
	}
	defer s.Close()

	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("SetupEventLogSource failed: %v", err)
	}

	return nil
}

func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s not found", serviceName)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return err
	}

	eventlog.Remove(serviceName)
	return nil
}

func StartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	return s.Start()
}

func StopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	return err
}

func GetWorkDir() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}
