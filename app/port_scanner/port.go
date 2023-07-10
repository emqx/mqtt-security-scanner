package port_scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"mqtt-security-scanner/config"
)

// Known MQTT ports
var mqttPort = map[int]bool{1883: true, 8883: true, 8083: true, 8084: true}

// HostPortScan scans the broker for any additional open ports
func HostPortScan(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("Host Port Scan")

	satisfied := true

	// First, scan broker for any additional open ports
	result := PortScanner(cfg.BrokerInfo.Host, true)
	for _, port := range result {
		satisfied = false
		si.Message = append(si.Message, fmt.Sprintf("TCP port %d in host %s is open", port, cfg.BrokerInfo.Host))
	}

	// Then, scan agent
	for _, host := range cfg.Hosts {
		result := PortScanner(host, false)

		for _, port := range result {
			satisfied = false
			si.Message = append(si.Message, fmt.Sprintf("TCP port %d in host %s is open", port, host))
		}
	}

	si.Pass = satisfied
	return si, nil
}

// PortScanner scans the host for open ports
func PortScanner(host string, isBroker bool) []int {
	numWorkers := 1000
	ports := make(chan int, numWorkers)

	var wg sync.WaitGroup
	var result []int
	for i := 0; i < numWorkers; i++ {
		go func() {
			for port := range ports {
				_, ok := mqttPort[port]
				if isBroker && ok {
					wg.Done()
					continue
				}
				address := fmt.Sprintf("%s:%d", host, port)
				conn, err := net.DialTimeout("tcp", address, 1*time.Second)
				if err != nil {
					// the port is closed or filtered.
					wg.Done()
					continue
				}
				conn.Close()
				fmt.Printf("%d open\n", port)
				result = append(result, port)
				wg.Done()
			}
		}()
	}

	for port := 1; port <= 65536; port++ {
		wg.Add(1)
		ports <- port
	}

	wg.Wait()
	close(ports)
	return result
}
