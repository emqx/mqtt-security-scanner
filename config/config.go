package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// ScanItem struct represents a single item to be scanned.
type ScanItem struct {
	Name    string   // The name of the scan item
	Pass    bool     // Whether the scan item has passed the scan
	Message []string // Message stores the reason why the scan failed
}

// NewScanItem function initializes a new ScanItem with the given name
func NewScanItem(name string) *ScanItem {
	return &ScanItem{
		Name:    name,
		Pass:    false,
		Message: make([]string, 0),
	}
}

type Config struct {
	BrokerInfo BrokerInfo `json:"broker"` // Broker-specific configurations
	Hosts      []string   `json:"hosts"`  // The list of hosts to be scanned
	Limit      Limit      `json:"limit"`  // Limit includes the various limitations and restrictions for the scan
}

type BrokerInfo struct {
	Host       string   `json:"host"`        // Broker's host address
	MQTTPort   int      `json:"mqtt_port"`   // Port for MQTT protocol
	MQTTSPort  int      `json:"mqtts_port"`  // Port for MQTT over SSL protocol
	WSPort     int      `json:"ws_port"`     // Port for WebSocket protocol
	WSSPort    int      `json:"wss_port"`    // Port for WebSocket over SSL protocol
	Username   string   `json:"username"`    // Username used for the broker
	Password   string   `json:"password"`    // Password used for the broker
	DenyTopics []string `json:"deny_topics"` // DenyTopics is a list of topics that are denied access
}

type Limit struct {
	ClientIDLen            int      `json:"client_id_len"`            // Length limit for client ID
	UsernameLen            int      `json:"username_len"`             // Length limit for username
	PasswordLen            int      `json:"password_len"`             // Length limit for password
	SupportTLSVersions     []uint16 `json:"support_tls_versions"`     // The list of supported TLS versions
	UnsupportedTLSVersions []uint16 `json:"unsupported_tls_versions"` // The list of unsupported TLS versions
	TopicLevel             int      `json:"topic_level"`              // Limit for topic levels
	TopicLen               int      `json:"topic_len"`                // Length limit for MQTT topic
	PayloadLen             int      `json:"payload_len"`              // Length limit for MQTT payload
	Connection             int      `json:"connection"`               // Limit for the number of connections
	Flapping               int      `json:"flapping"`                 // Limit for the number of flapping connections
}

// InitConfig function initializes the configuration by reading from the configuration file
func InitConfig(configPath string) *Config {
	config, err := initConfigFile(configPath)
	if err != nil {
		log.Panicln(err)
	}
	return config
}

func initConfigFile(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		err := fmt.Errorf("Failed to find config file, %s", configPath)
		return nil, err
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cf Config
	if err = json.Unmarshal(configData, &cf); err != nil {
		return nil, err
	}
	return &cf, nil
}
