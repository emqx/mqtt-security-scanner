package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"mqtt-security-scanner/app/mqtt_scanner"
	"mqtt-security-scanner/app/port_scanner"
	"mqtt-security-scanner/config"
)

type ScannerFunc func(*config.Config) (*config.ScanItem, error)

func main() {
	fReport := flag.String("r", "stdout", "report output type(stdout/file)")
	configPath := flag.String("config", "config/config.json", "config address")
	flag.Parse()

	// Initialize configuration
	cfg := config.InitConfig(*configPath)

	// Define items of scanners
	scanners := map[string]ScannerFunc{
		// protocol related scanner
		"Invalid MQTT Message":       mqtt_scanner.InvalidMQTTProtocolScanner,
		"Invalid Websocket Protocol": mqtt_scanner.InvalidWSProtocolScanner,

		// MQTT client related scanner
		"Client Authentication":       mqtt_scanner.MQTTClientAuthentication,
		"MQTT Client Username Length": mqtt_scanner.MQTTClientUsernameLength,
		"MQTT Client password Length": mqtt_scanner.MQTTClientPasswordLength,
		"MQTT Client ID Length":       mqtt_scanner.MQTTClientIDLength,
		"MQTT Client Flapping":        mqtt_scanner.MQTTClientFlapping,

		// MQTT message related scanner
		"MQTT Topic Level":            mqtt_scanner.MQTTTopicLevel,
		"MQTT Topic Length":           mqtt_scanner.MQTTTopicLength,
		"MQTT Message Payload Length": mqtt_scanner.MQTTMessagePayloadLength,

		// port scanner
		"Host Port Scan": port_scanner.HostPortScan,
	}

	// Set tls scanner
	if cfg.BrokerInfo.TLS {
		scanners["TLS Version"] = mqtt_scanner.TLSVersionsScanner
	}

	// Create a buffered channel to store the results of each scan
	scannerNum := len(scanners)
	results := make(chan *config.ScanItem, scannerNum+1)

	// Launch each scanner in separate goroutine
	var wg sync.WaitGroup
	wg.Add(scannerNum)
	for name, scanner := range scanners {
		go func(name string, scanner ScannerFunc) {
			defer wg.Done()
			results <- runScanner(cfg, name, scanner)
		}(name, scanner)
	}

	// Record the starting time and wait for all scans to complete
	start := time.Now()
	wg.Wait()

	// Delay execute MQTT client connection scanner, because it will affect other scanners
	results <- runScanner(cfg, "MQTT Client Connection", mqtt_scanner.MQTTClientConnection)

	close(results)

	fmt.Println(time.Since(start))
	// Output results based on the chosen mode
	output(results, *fReport)
}

func runScanner(cfg *config.Config, name string, scanner ScannerFunc) *config.ScanItem {
	fmt.Printf("Start running scanner item [%s]\n", name)
	si, err := scanner(cfg)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to execute scanner item [%s], %v", name, err)
		panic(errMsg)
	}
	fmt.Printf("Finish running scanner item [%s]\n", name)
	return si
}

// 'output' function takes a channel of scan results and a mode string, it supports 'stdout' and 'file' mode
// 'stdout' mode outputs the results directly to the terminal
// 'file' mode writes results to a 'result.txt' file
func output(results chan *config.ScanItem, mode string) {
	var buf bytes.Buffer
	for si := range results {
		if !si.Pass {
			buf.WriteString(fmt.Sprintf("[%s]\t do not pass: %s\n", si.Name, strings.Join(si.Message, ", ")))
			continue
		}
		buf.WriteString(fmt.Sprintf("[%s]\t pass\n", si.Name))
	}

	switch mode {
	case "stdout":
		fmt.Print(buf.String())
	case "file":
		file, err := os.Create("result.txt")
		if err != nil {
			errMsg := fmt.Sprintf("Failed to create scan result file, %v", err)
			panic(errMsg)
		}
		defer file.Close()

		_, err = buf.WriteTo(file)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to write scan result, %v", err)
			panic(errMsg)
		}
	default:
		panic("Unsupported output format")
	}
}
