package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

type Server struct {
	engine *gin.Engine
	addr   string
	srv    *http.Server
}

type Pac struct {
	URL string `json:"url"`
}

type Global struct {
	HOST   string `json:"host"`
	PORT   string `json:"port"`
	BYPASS string `json:"bypass"`
}

// Validate PAC URL
func validatePacURL(urlStr string) (string, error) {
	if strings.ContainsAny(urlStr, "&|;`$(){}[]<>\\") {
		return "", errors.New("URL contains illegal characters")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("URL must use http or https protocol")
	}

	return urlStr, nil
}

// Validate global proxy parameters
func validateGlobalProxy(host, port, bypass string) error {
	if strings.ContainsAny(host, "&|;`$(){}[]<>\\") {
		return errors.New("Host contains illegal characters")
	}

	_, err := strconv.Atoi(port)
	if err != nil {
		return errors.New("Port must be numeric")
	}

	domains := strings.Split(bypass, " ")
	for _, domain := range domains {
		if strings.ContainsAny(domain, "&|;`$(){}[]<>\\") {
			return errors.New("Bypass domain contains illegal characters")
		}
	}

	return nil
}

// Get network service list
func getNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listnetworkserviceorder")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var services []string

	for _, line := range lines {
		if strings.HasPrefix(line, "(") && strings.Contains(line, ")") {
			service := strings.TrimSpace(strings.SplitN(line, ")", 2)[1])
			services = append(services, service)
		}
	}

	return services, nil
}

// Turn off all proxies for a service
func turnOffProxies(service string) error {
	commands := [][]string{
		{"networksetup", "-setautoproxystate", service, "off"},
		{"networksetup", "-setproxyautodiscovery", service, "off"},
		{"networksetup", "-setwebproxystate", service, "off"},
		{"networksetup", "-setsecurewebproxystate", service, "off"},
		{"networksetup", "-setsocksfirewallproxystate", service, "off"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	return nil
}

// Set PAC proxy for a service
func setPACProxy(service, pacURL string) error {
	if err := turnOffProxies(service); err != nil {
		return err
	}

	// Set PAC URL
	cmd1 := exec.Command("networksetup", "-setautoproxyurl", service, pacURL)
	if err := cmd1.Run(); err != nil {
		return err
	}

	// Enable PAC
	cmd2 := exec.Command("networksetup", "-setautoproxystate", service, "on")
	if err := cmd2.Run(); err != nil {
		return err
	}

	cmd3 := exec.Command("networksetup", "-setproxyautodiscovery", service, "on")
	if err := cmd3.Run(); err != nil {
		return err
	}

	return nil
}

// Set global proxy for a service
func setGlobalProxy(service, host, port, bypass string) error {
	if err := turnOffProxies(service); err != nil {
		return err
	}

	commands := [][]string{
		{"networksetup", "-setwebproxy", service, host, port},
		{"networksetup", "-setsecurewebproxy", service, host, port},
		{"networksetup", "-setsocksfirewallproxy", service, host, port},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	// Set bypass domains if provided
	if bypass != "" {
		cmd := exec.Command("networksetup", "-setproxybypassdomains", service, bypass)
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	return nil
}

func NewServer(addr string) *Server {
	engine := gin.Default()
	srv := &http.Server{
		Handler: engine,
	}

	return &Server{
		engine: engine,
		addr:   addr,
		srv:    srv,
	}
}

func (s *Server) setupRoutes() {
	s.engine.POST("/pac", func(c *gin.Context) {
		var pac Pac

		if err := c.ShouldBindJSON(&pac); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Validate PAC URL
		validURL, err := validatePacURL(pac.URL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Get all network services
		services, err := getNetworkServices()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get network services: " + err.Error(),
			})
			return
		}

		// Set PAC proxy for each service
		var errorMessages []string
		for _, service := range services {
			if err := setPACProxy(service, validURL); err != nil {
				errorMessages = append(errorMessages, "Failed to set PAC proxy for "+service+": "+err.Error())
			} else {
				log.Printf("Set PAC proxy for %s to %s", service, validURL)
			}
		}

		if len(errorMessages) > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": strings.Join(errorMessages, "\n"),
			})
			return
		}

		c.String(200, "PAC proxy has been set for all services")
	})

	s.engine.POST("/global", func(c *gin.Context) {
		var global Global

		if err := c.ShouldBindJSON(&global); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Validate global proxy parameters
		if err := validateGlobalProxy(global.HOST, global.PORT, global.BYPASS); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Get all network services
		services, err := getNetworkServices()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get network services: " + err.Error(),
			})
			return
		}

		// Set global proxy for each service
		var errorMessages []string
		for _, service := range services {
			if err := setGlobalProxy(service, global.HOST, global.PORT, global.BYPASS); err != nil {
				errorMessages = append(errorMessages, "Failed to set global proxy for "+service+": "+err.Error())
			} else {
				log.Printf("Set global proxy for %s to %s:%s", service, global.HOST, global.PORT)
			}
		}

		if len(errorMessages) > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": strings.Join(errorMessages, "\n"),
			})
			return
		}

		c.String(200, "Global proxy has been set for all services")
	})

	s.engine.GET("/off", func(c *gin.Context) {
		// Get all network services
		services, err := getNetworkServices()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get network services: " + err.Error(),
			})
			return
		}

		// Turn off proxy for each service
		var errorMessages []string
		for _, service := range services {
			if err := turnOffProxies(service); err != nil {
				errorMessages = append(errorMessages, "Failed to turn off proxy for "+service+": "+err.Error())
			} else {
				log.Printf("Turned off proxy for %s", service)
			}
		}

		if len(errorMessages) > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": strings.Join(errorMessages, "\n"),
			})
			return
		}

		c.String(200, "Proxy has been turned off for all services")
	})
}

func (s *Server) Start() error {
	s.setupRoutes()

	if err := os.RemoveAll(s.addr); err != nil {
		return err
	}

	listener, err := net.Listen("unix", s.addr)
	if err != nil {
		return err
	}

	if err := os.Chmod(s.addr, 0666); err != nil {
		return err
	}

	go func() {
		if err := s.srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v\n", err)
		}
	}()

	return nil
}

func main() {
	server := NewServer("/tmp/mihomo-party-helper.sock")

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use http.Server's Shutdown method
	if err := server.srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	if err := os.RemoveAll(server.addr); err != nil {
		log.Printf("Failed to remove socket file: %v", err)
	}
}
