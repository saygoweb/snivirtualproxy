package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	LogFile string
	Server  struct {
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
	configFilePath := "/etc/snivirtualproxy/config.yml"
	if fileExists("./config.yml") {
		configFilePath = "./config.yml"
	}
	configContent, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		log.Fatalf("Cannot read config from '%s': %v", configFilePath, err)
	}
	err = yaml.Unmarshal(configContent, config)
	if err != nil {
		log.Fatalf("Cannot parse config from '%s': %v", configFilePath, err)
	}
}

func startLogger() {
	file, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0660)
	if err != nil {
		log.Fatalf("Cannot open logfile '%s': %v", config.LogFile, err)
	}
	InfoLogger = log.New(file, "INFO:  ", log.Ldate|log.Ltime)
	WarningLogger = log.New(file, "WARN:  ", log.Ldate|log.Ltime)
	ErrorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	DebugLogger = log.New(file, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	log.SetFlags(log.Lshortfile)
	config.readConfig()
	startLogger()
	InfoLogger.Printf("snivirtualproxy starting ...")

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

		// Note that ServeHttp is non blocking and uses a go routine under the hood
		proxy.ServeHTTP(res, req)
	})

	http.Serve(listener, nil)

	InfoLogger.Println("snivirtualproxy shutdown")
}

func returnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	InfoLogger.Printf("SNI %s", helloInfo.ServerName)

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
