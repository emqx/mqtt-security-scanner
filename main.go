package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"mqtt-security-scanner/app/mqtt_scanner"
	"mqtt-security-scanner/app/port_scanner"
	"mqtt-security-scanner/config"
)

type ScannerFunc func(*config.Config) (*config.ScanItem, error)

func main() {
	fReport := flag.String("r", "stdout", "report output type(stdout/file)")
	configPath := flag.String("config", "config.json", "config address")
	flag.Parse()

	// Initialize configuration
	cfg := config.InitConfig(*configPath)

	// Define items of scanners
	scanners := []func(*config.Config) (*config.ScanItem, error){
		// protocol related scanner
		mqtt_scanner.InvalidMQTTProtocolScanner,
		mqtt_scanner.InvalidWSProtocolScanner,

		// MQTT client related scanner
		mqtt_scanner.MQTTClientAuthentication,
		mqtt_scanner.MQTTClientUsernameLength,
		mqtt_scanner.MQTTClientPasswordLength,
		mqtt_scanner.MQTTClientIDLength,
		mqtt_scanner.MQTTClientFlapping,

		// MQTT message related scanner
		mqtt_scanner.MQTTTopicLevel,
		mqtt_scanner.MQTTTopicLength,
		mqtt_scanner.MQTTMessagePayloadLength,

		// port scanner
		port_scanner.HostPortScan,
	}

	// Set tls scanner
	if cfg.BrokerInfo.TLS {
		scanners = append(scanners, mqtt_scanner.TLSVersionsScanner)
	}

	// Create a buffered channel to store the results of each scan
	scannerNum := len(scanners)
	results := make(chan *config.ScanItem, scannerNum+1)

	// Launch each scanner in separate goroutine
	var wg sync.WaitGroup
	wg.Add(scannerNum)
	for _, scanner := range scanners {
		go func(scanner ScannerFunc) {
			defer wg.Done()

			si, err := scanner(cfg)
			// If a scanner returns an error, panic
			if err != nil {
				errMsg := fmt.Sprintf("Failed to execute scanner item [%s], %v", si.Name, err)
				panic(errMsg)
			}
			results <- si
		}(scanner)
	}

	// Record the starting time and wait for all scans to complete
	start := time.Now()
	wg.Wait()

	// Delay execute MQTT client connection scanner, because it will affect other scanners
	func(scanner ScannerFunc) {
		si, err := scanner(cfg)
		// If a scanner returns an error, panic
		if err != nil {
			errMsg := fmt.Sprintf("Failed to execute scanner item [%s], %v", si.Name, err)
			panic(errMsg)
		}
		results <- si
	}(mqtt_scanner.MQTTClientConnection)

	close(results)
	fmt.Println(time.Since(start))

	// Output results based on the chosen mode
	output(results, *fReport)
}

// 'output' function takes a channel of scan results and a mode string, it supports 'stdout' and 'file' mode
// 'stdout' mode outputs the results directly to the terminal
// 'file' mode writes results to a 'result.txt' file
func output(results chan *config.ScanItem, mode string) {
	var buf bytes.Buffer
	for si := range results {
		if !si.Pass {
			buf.WriteString(fmt.Sprintf("[%s]\t do not pass, %v\n", si.Name, si.Message))
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
