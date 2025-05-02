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

var get_services = `get_services() {
    networksetup -listnetworkserviceorder | grep "^([0-9])" | sed -e 's/^([0-9]) //'
}`

var turn_off = `while IFS= read -r service; do
    echo "Turning off proxy for '$service'..."
    networksetup -setautoproxystate "$service" off
	networksetup -setproxyautodiscovery "$service" off
    networksetup -setwebproxystate "$service" off
    networksetup -setsecurewebproxystate "$service" off
    networksetup -setsocksfirewallproxystate "$service" off
done < <(get_services)
echo "Proxy has been turned off for all services"`

var set_pac = `while IFS= read -r service; do
    echo "Setting PAC proxy for '$service'..."
	networksetup -setautoproxystate "$service" off
	networksetup -setproxyautodiscovery "$service" off
    networksetup -setwebproxystate "$service" off
    networksetup -setsecurewebproxystate "$service" off
    networksetup -setsocksfirewallproxystate "$service" off

    networksetup -setautoproxyurl "$service" "${pac.URL}"
    networksetup -setautoproxystate "$service" on
	networksetup -setproxyautodiscovery "$service" on
done < <(get_services)
echo "PAC proxy has been set to ${pac.URL} for all services"`

var set_global = `while IFS= read -r service; do
    echo "Setting global proxy for '$service'..."
	networksetup -setautoproxystate "$service" off
	networksetup -setproxyautodiscovery "$service" off
    networksetup -setwebproxystate "$service" off
    networksetup -setsecurewebproxystate "$service" off
    networksetup -setsocksfirewallproxystate "$service" off

    networksetup -setwebproxy "$service" "${global.HOST}" "${global.PORT}"
    networksetup -setsecurewebproxy "$service" "${global.HOST}" "${global.PORT}"
    networksetup -setsocksfirewallproxy "$service" "${global.HOST}" "${global.PORT}"
    networksetup -setproxybypassdomains "$service" "${global.BYPASS}"
done < <(get_services)
echo "Global proxy has been set to ${global.HOST}:${global.PORT} for all services"`

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

		script := get_services + "\n" + set_pac
		script = strings.Replace(script, "${pac.URL}", validURL, -1)
		cmd := exec.Command("bash", "-c", script)
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  err.Error(),
				"output": string(output),
			})
			return
		}
		log.Printf("Output: %s", output)
		c.String(200, "Proxy has been set as pac mode for all services")
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

		script := get_services + "\n" + set_global
		script = strings.Replace(script, "${global.HOST}", global.HOST, -1)
		script = strings.Replace(script, "${global.PORT}", global.PORT, -1)
		script = strings.Replace(script, "${global.BYPASS}", global.BYPASS, -1)
		cmd := exec.Command("bash", "-c", script)
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  err.Error(),
				"output": string(output),
			})
			return
		}
		log.Printf("Output: %s", output)
		c.String(200, "Proxy has been set as global mode for all services")
	})

	s.engine.GET("/off", func(c *gin.Context) {
		script := get_services + "\n" + turn_off
		cmd := exec.Command("bash", "-c", script)
		output, err := cmd.CombinedOutput()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  err.Error(),
				"output": string(output),
			})
			return
		}
		log.Printf("Output: %s", output)
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

	// 使用 http.Server 的 Shutdown 方法
	if err := server.srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	if err := os.RemoveAll(server.addr); err != nil {
		log.Printf("Failed to remove socket file: %v", err)
	}
}
