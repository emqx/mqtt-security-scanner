package mqtt_scanner

import (
	"math/rand"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GenerateRandomTopic generates a random MQTT topic with the specified number of levels
func GenerateRandomTopic(levels int) string {
	rand.Seed(time.Now().UnixNano())

	var topicLevels []string
	for i := 0; i < levels; i++ {
		topicLevels = append(topicLevels, RandomString(5))
	}

	return strings.Join(topicLevels, "/")
}

// RandomString generates a random string of the specified length
func RandomString(length int) string {

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// VerifyMQTTConnection verifies if the MQTT client can establish a connection with the MQTT broker
func VerifyMQTTConnection(client mqtt.Client) bool {
	token := client.Connect()
	return !(token.Wait() && token.Error() != nil)
}
