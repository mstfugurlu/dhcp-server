package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/mstfugurlu/dhcp-server/internal/dhcp"
	"github.com/mstfugurlu/dhcp-server/internal/server"
	"github.com/mstfugurlu/dhcp-server/internal/service"
	"github.com/mstfugurlu/dhcp-server/internal/store"
)

type Config struct {
	ServerIP string `json:"server_ip"`
	WebPort  int    `json:"web_port"`
	DBPath   string `json:"db_path"`
}

func main() {
	install := flag.Bool("install", false, "Install Windows service")
	uninstall := flag.Bool("uninstall", false, "Uninstall Windows service")
	start := flag.Bool("start", false, "Start the service")
	stop := flag.Bool("stop", false, "Stop the service")
	configPath := flag.String("config", "", "Config file path")
	flag.Parse()

	if *install {
		if err := service.InstallService(); err != nil {
			log.Fatalf("Failed to install service: %v", err)
		}
		fmt.Println("Service installed successfully")
		return
	}

	if *uninstall {
		if err := service.UninstallService(); err != nil {
			log.Fatalf("Failed to uninstall service: %v", err)
		}
		fmt.Println("Service uninstalled successfully")
		return
	}

	if *start {
		if err := service.StartService(); err != nil {
			log.Fatalf("Failed to start service: %v", err)
		}
		fmt.Println("Service started")
		return
	}

	if *stop {
		if err := service.StopService(); err != nil {
			log.Fatalf("Failed to stop service: %v", err)
		}
		fmt.Println("Service stopped")
		return
	}

	err := service.RunAsService(func() error {
		return run(*configPath)
	})
	if err != nil {
		log.Fatal(err)
	}
}

func run(configPath string) error {
	workDir := service.GetWorkDir()

	if configPath == "" {
		configPath = filepath.Join(workDir, "config.json")
	}

	cfg := loadConfig(configPath)

	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = filepath.Join(workDir, "dhcp.db")
	}

	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	serverIP := net.ParseIP(cfg.ServerIP)
	if serverIP == nil {
		serverIP = getLocalIP()
	}

	// start DHCP server
	dhcpServer := dhcp.NewServer(st, serverIP)
	go func() {
		if err := dhcpServer.Start(); err != nil {
			log.Printf("DHCP server error: %v", err)
		}
	}()

	// start web server
	webAddr := fmt.Sprintf(":%d", cfg.WebPort)
	if cfg.WebPort == 0 {
		webAddr = ":8080"
	}

	webServer := server.NewWebServer(st, webAddr)
	return webServer.Start()
}

func loadConfig(path string) Config {
	cfg := Config{
		WebPort: 8080,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}

	json.Unmarshal(data, &cfg)
	return cfg
}

func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return net.ParseIP("0.0.0.0")
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}

	return net.ParseIP("0.0.0.0")
}
