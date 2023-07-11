package mqtt_scanner

import (
	"math/rand"
	"strings"
	"time"
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
