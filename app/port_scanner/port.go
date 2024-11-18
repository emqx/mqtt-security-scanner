package port_scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"mqtt-security-scanner/config"
)

// Known MQTT ports
var mqttPort = map[int]bool{1883: true, 8883: true, 8083: true, 8084: true, 8443: true}

// HostPortScan scans the broker for any additional open ports
func HostPortScan(cfg *config.Config) (*config.ScanItem, error) {
	si := config.NewScanItem("Host Port Scan")
	si.Pass = true
	scan := func(host string, isBroker bool) {
		result := PortScanner(host, isBroker)
		if len(result) == 0 {
			return
		}

		si.Pass = false
		for _, port := range result {
			si.Message = append(si.Message, fmt.Sprintf("TCP port %d in host %s is open", port, host))
		}
	}

	// Scan broker
	scan(cfg.BrokerInfo.Host, true)
	// scan agent
	for _, host := range cfg.Hosts {
		scan(host, false)
	}

	return si, nil
}

// PortScanner scans the host for open ports
func PortScanner(host string, isBroker bool) []int {
	numWorkers := 1000
	ports := make(chan int, numWorkers)

	var wg sync.WaitGroup
	var lk sync.Mutex
	var result []int
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()

			openPorts := []int{}
			for port := range ports {
				_, ok := mqttPort[port]
				if isBroker && ok {
					continue
				}
				address := fmt.Sprintf("%s:%d", host, port)
				conn, err := net.DialTimeout("tcp", address, 1*time.Second)
				if err != nil {
					// the port is closed or filtered.
					continue
				}
				conn.Close()
				openPorts = append(openPorts, port)
			}

			if len(openPorts) != 0 {
				lk.Lock()
				result = append(result, openPorts...)
				lk.Unlock()
			}
		}()
	}

	for port := 1; port <= 65536; port++ {
		ports <- port
	}

	close(ports)
	wg.Wait()
	return result
}
