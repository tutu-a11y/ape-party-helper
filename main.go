package main

import (
	"context"
	"errors"
	"fmt"
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

const Version = "1.0.0"

func init() {
	// Gin log output to stdout
	gin.DefaultWriter = os.Stdout
	gin.DefaultErrorWriter = os.Stderr
}

type Server struct {
	engine   *gin.Engine
	addr     string
	srv      *http.Server
	listener net.Listener
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
		return "", errors.New("url contains illegal characters")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("url must use http or https protocol")
	}

	return urlStr, nil
}

// Validate global proxy parameters
func validateGlobalProxy(host, port, bypass string) error {
	if strings.ContainsAny(host, "&|;`$(){}[]\\") {
		return errors.New("host contains illegal characters")
	}

	_, err := strconv.Atoi(port)
	if err != nil {
		return errors.New("port must be numeric")
	}

	// Comma-separated and space-separated bypass domain lists
	var domains []string
	if strings.Contains(bypass, ",") {
		domains = strings.Split(bypass, ",")
	} else {
		domains = strings.Split(bypass, " ")
	}

	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		// Allow <local> format, and wildcard *
		if strings.ContainsAny(domain, "&|;`$(){}[]\\") {
			// Whether special format like <local>
			if !(strings.HasPrefix(domain, "<") && strings.HasSuffix(domain, ">")) {
				return errors.New("bypass domain contains illegal characters")
			}
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

		// Skip hardware port lines like "(Hardware Port: ..., Device: ...)"
		if strings.HasPrefix(line, "(") && strings.Contains(line, ")") && !strings.Contains(line, "Hardware Port:") {

			parts := strings.SplitN(line, ") ", 2)
			if len(parts) == 2 {
				service := strings.TrimSpace(parts[1])
				if service != "" && service != "*" {

					service = strings.TrimPrefix(service, "*")
					service = strings.TrimSpace(service)
					services = append(services, service)
				}
			}
		}
	}

	if len(services) == 0 {
		return nil, errors.New("no network services found")
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
		// Split bypass domains using the same logic as validation
		var domains []string
		if strings.Contains(bypass, ",") {
			domains = strings.Split(bypass, ",")
		} else {
			domains = strings.Split(bypass, " ")
		}

		// prepare arguments
		var cleanDomains []string
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				cleanDomains = append(cleanDomains, domain)
			}
		}

		if len(cleanDomains) > 0 {
			args := []string{"-setproxybypassdomains", service}
			args = append(args, cleanDomains...)
			cmd := exec.Command("networksetup", args...)
			if err := cmd.Run(); err != nil {
				return err
			}
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
		var successCount int
		for _, service := range services {
			if err := setPACProxy(service, validURL); err != nil {
				errorMessages = append(errorMessages, "Failed to set PAC proxy for "+service+": "+err.Error())
			} else {
				successCount++
			}
		}

		if successCount > 0 {
			if len(errorMessages) > 0 {
				c.String(200, fmt.Sprintf("PAC proxy set for %d/%d services. Some errors occurred: %s",
					successCount, len(services), strings.Join(errorMessages, "; ")))
			} else {
				c.String(200, "PAC proxy has been set for all services")
			}
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to set PAC proxy for any service: " + strings.Join(errorMessages, "; "),
			})
		}
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

		services, err := getNetworkServices()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get network services: " + err.Error(),
			})
			return
		}

		// Process global proxy settings
		var errorMessages []string
		var successCount int
		for _, service := range services {
			if err := setGlobalProxy(service, global.HOST, global.PORT, global.BYPASS); err != nil {
				errorMessages = append(errorMessages, "Failed to set global proxy for "+service+": "+err.Error())
			} else {
				successCount++
			}
		}

		if successCount > 0 {
			if len(errorMessages) > 0 {
				c.String(200, fmt.Sprintf("Global proxy set for %d/%d services. Some errors occurred: %s",
					successCount, len(services), strings.Join(errorMessages, "; ")))
			} else {
				c.String(200, "Global proxy has been set for all services")
			}
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to set global proxy for any service: " + strings.Join(errorMessages, "; "),
			})
		}
	})

	s.engine.GET("/off", func(c *gin.Context) {
		services, err := getNetworkServices()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get network services: " + err.Error(),
			})
			return
		}

		// Turn off proxy for each service
		var errorMessages []string
		var successCount int
		for _, service := range services {
			if err := turnOffProxies(service); err != nil {
				errorMessages = append(errorMessages, "Failed to turn off proxy for "+service+": "+err.Error())
			} else {
				successCount++
			}
		}

		// If at least one service succeeded, consider it a partial success
		if successCount > 0 {
			if len(errorMessages) > 0 {
				c.String(200, fmt.Sprintf("Proxy turned off for %d/%d services. Some errors occurred: %s",
					successCount, len(services), strings.Join(errorMessages, "; ")))
			} else {
				c.String(200, "Proxy has been turned off for all services")
			}
		} else {
			// Only return error if ALL services failed
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to turn off proxy for any service: " + strings.Join(errorMessages, "; "),
			})
		}
	})
}

// Create initial socket
func (s *Server) createSocket() error {
	listener, err := net.Listen("unix", s.addr)
	if err != nil {
		return err
	}

	// Store listener reference
	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.addr, 0666); err != nil {
		return err
	}

	// Start server in goroutine
	go func() {
		if err := s.srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			// Server error, silently continue
		}
	}()

	return nil
}

func (s *Server) Start() error {
	s.setupRoutes()

	// Remove existing socket file if exists
	if err := os.RemoveAll(s.addr); err != nil {
		return err
	}

	// Create new socket listener
	if err := s.createSocket(); err != nil {
		return err
	}

	// Start signal handler for socket recreation
	s.startSignalHandler()

	return nil
}

// Signal handler to recreate socket on SIGUSR1
func (s *Server) startSignalHandler() {
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGUSR1)

		for range sigChan {
			if _, err := os.Stat(s.addr); os.IsNotExist(err) {
				s.recreateListener()
			}
		}
	}()
}

// Recreate the entire listener when socket file is missing
func (s *Server) recreateListener() error {
	// Store reference to old listener but don't close it immediately
	oldListener := s.listener

	// Remove any existing socket file
	os.RemoveAll(s.addr)

	// Create new listener
	listener, err := net.Listen("unix", s.addr)
	if err != nil {
		return err
	}

	// Set socket permissions
	if err := os.Chmod(s.addr, 0666); err != nil {
		listener.Close()
		return err
	}

	// Update listener reference before starting server
	s.listener = listener

	// Create a new server instance for the new listener
	newSrv := &http.Server{
		Handler: s.engine,
	}

	// Start new server goroutine
	go func() {
		if err := newSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
			// Server error, silently continue
		}
	}()

	// Don't actively close the old listener
	// This prevents the socket file from being deleted
	_ = oldListener

	// Verify socket file exists after a short delay
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(s.addr); err != nil {
		return err
	}

	return nil
}

func main() {
	server := NewServer("/tmp/ape-party-helper.sock")

	if err := server.Start(); err != nil {
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use http.Server's Shutdown method
	if err := server.srv.Shutdown(ctx); err != nil {
		os.Exit(1)
	}

	if server.listener != nil {
		server.listener.Close()
	}

	os.RemoveAll(server.addr)
}
