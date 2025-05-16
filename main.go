package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gopkg.in/yaml.v2"
)

const version = "1.2.0"

type Config struct {
	ConfigFile string
	LogFile    string
	Server     struct {
		Bind        string
		UpstreamUrl string
	}
	Ssl struct {
		Certificate string
		Key         string
	}
}

var config Config

var (
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
	DebugLogger   *log.Logger
)

func fileExists(filePath string) bool {
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return !fileInfo.IsDir()
}

func (config *Config) readConfig() {
	configFilePath := flag.String("config", "/etc/snivirtualproxy/config.yml", "Configuration file")
	showVersion := flag.Bool("version", false, "Display version and exit")
	flag.Parse() // Ensure flag.Parse() is called before dereferencing configFilePath
	if *showVersion {
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	if configFilePath == nil || !fileExists(*configFilePath) {
		log.Fatalf("Cannot find config file '%s'", *configFilePath)
	}
	configContent, err := os.ReadFile(*configFilePath)
	if err != nil {
		log.Fatalf("Cannot read config from '%s': %v", *configFilePath, err)
	}
	err = yaml.Unmarshal(configContent, config)
	if err != nil {
		log.Fatalf("Cannot parse config from '%s': %v", *configFilePath, err)
	}
	config.ConfigFile = *configFilePath
}

var logFile *os.File

func loggerStart() {
	logFile, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0660)
	if err != nil {
		log.Fatalf("Cannot open logfile '%s': %v", config.LogFile, err)
	}
	InfoLogger = log.New(logFile, "INFO:  ", log.Ldate|log.Ltime)
	WarningLogger = log.New(logFile, "WARN:  ", log.Ldate|log.Ltime)
	ErrorLogger = log.New(logFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	DebugLogger = log.New(logFile, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func loggerReopen() {
	logFile.Close()
	logFile, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0660)
	if err != nil {
		log.Printf("Cannot open logfile '%s': %v", config.LogFile, err)
	}
	InfoLogger.SetOutput(logFile)
	WarningLogger.SetOutput(logFile)
	ErrorLogger.SetOutput(logFile)
	DebugLogger.SetOutput(logFile)

	InfoLogger.Println("Log file refresh")
}

func main() {
	log.SetFlags(log.Lshortfile)
	config.readConfig()
	loggerStart()
	fmt.Printf("snivirtualproxy v%s\n", version)
	InfoLogger.Printf("snivirtualproxy %s starting ...", version)
	InfoLogger.Printf("with config %s", config.ConfigFile)

	// Signal Handling
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		sig := <-signals
		log.Printf("Caught %s", sig)
		if sig == syscall.SIGHUP {
			loggerReopen()
		} else if sig == syscall.SIGINT || sig == syscall.SIGTERM {
			InfoLogger.Fatalf("snivirtualproxy terminated by %s", sig)
		}
	}()

	tlsConfig := &tls.Config{
		GetCertificate: returnCert,
	}
	listener, err := tls.Listen("tcp", config.Server.Bind, tlsConfig)
	if err != nil {
		ErrorLogger.Fatalf("Cannot bind to socket '%s': %v", config.Server.Bind, err)
		return
	}
	defer listener.Close()
	InfoLogger.Printf("snivirtualproxy started. Listening on %s", config.Server.Bind)

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		url, _ := url.Parse(config.Server.UpstreamUrl)

		// create the reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(url)

		// Update the headers to allow for SSL redirection
		req.URL.Host = url.Host
		req.URL.Scheme = url.Scheme
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Host = url.Host

		// Add the original client IP to the X-Forwarded-For header
		clientIP := req.RemoteAddr
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)

		// Note that ServeHttp is non blocking and uses a go routine under the hood
		proxy.ServeHTTP(res, req)
	})

	http.Serve(listener, nil)

	InfoLogger.Println("snivirtualproxy shutdown")
}

func returnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ip := helloInfo.Conn.RemoteAddr().String()
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}
	InfoLogger.Printf("SNI req %s for %s", ip, helloInfo.ServerName)

	// templateCertificate := "/etc/letsencrypt/live/$(SNI_SERVER_NAME)/cert.pem"
	// templateKey := "/etc/letsencrypt/live/$(SNI_SERVER_NAME)/privkey.pem"
	templateCertificate := config.Ssl.Certificate
	templateKey := config.Ssl.Key

	certificateFilePath := strings.Replace(templateCertificate, "$(SNI_SERVER_NAME)", helloInfo.ServerName, -1)
	keyFilePath := strings.Replace(templateKey, "$(SNI_SERVER_NAME)", helloInfo.ServerName, -1)

	certificate, err := tls.LoadX509KeyPair(certificateFilePath, keyFilePath)
	if err != nil {
		log.Println(err)
		return nil, nil
	}

	return &certificate, nil
}
