package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/blck-snwmn/proxymitm"
)

func main() {
	var (
		addr     = flag.String("addr", ":8080", "proxy listen address")
		certPath = flag.String("cert", "./ca.crt", "path to CA certificate")
		keyPath  = flag.String("key", "./ca.key", "path to CA private key")
		logLevel = flag.String("loglevel", "info", "log level (debug, info, warn, error)")
	)
	flag.Parse()

	// Set log level
	var level proxymitm.LogLevel
	switch *logLevel {
	case "debug":
		level = proxymitm.LogLevelDebug
	case "info":
		level = proxymitm.LogLevelInfo
	case "warn":
		level = proxymitm.LogLevelWarn
	case "error":
		level = proxymitm.LogLevelError
	default:
		level = proxymitm.LogLevelInfo
	}
	logger := proxymitm.NewDefaultLogger(level)

	// Create MITM proxy
	mp, err := proxymitm.CreateMitmProxy(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("Failed to create MITM proxy: %v", err)
	}

	// Add logging interceptor
	loggingInterceptor := proxymitm.NewLoggingInterceptor(logger)
	mp.AddInterceptor(loggingInterceptor)

	// Add content modifier interceptor
	contentModifier := proxymitm.NewContentModifierInterceptor(logger)
	contentModifier.AddRequestHeaderModification("User-Agent", "MITM-Proxy/1.0")
	contentModifier.AddResponseHeaderModification("X-Proxied-By", "MITM-Proxy")
	contentModifier.AddBodyReplacement("<title>", "<title>Modified by MITM-Proxy - ")
	mp.AddInterceptor(contentModifier)

	// Add filtering interceptor
	filteringInterceptor := proxymitm.NewFilteringInterceptor(logger)
	filteringInterceptor.AddBlockedHost("ads.example.com")
	filteringInterceptor.AddBlockedPath("/ads/")
	filteringInterceptor.SetBlockResponse(http.StatusForbidden, "403 Forbidden", "This content is blocked by MITM-Proxy")
	mp.AddInterceptor(filteringInterceptor)

	// Add request ID interceptor
	requestIDInterceptor := proxymitm.NewRequestIDInterceptor(logger)
	mp.AddInterceptor(requestIDInterceptor)

	// Start the server
	log.Printf("Starting MITM proxy on %s", *addr)
	log.Printf("Using CA certificate: %s", *certPath)
	log.Printf("Using CA private key: %s", *keyPath)
	log.Printf("Log level: %s", *logLevel)
	log.Fatal(http.ListenAndServe(*addr, mp))
}
