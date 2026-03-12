package network

import (
	"fmt"
	"net"
	"time"
)

func CheckPortAvailability(port string) error {
	address := net.JoinHostPort("127.0.0.1", port)

	// Try to listen on the port
	l, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("port %s is already in use or restricted. Please choose another port with --web-port", port)
	}
	l.Close()
	return nil
}

func VerifyServerIsUp(port string) bool {
	address := net.JoinHostPort("127.0.0.1", port)
	timeout := 2 * time.Second

	// Give the server a moment to initialize if calling immediately after start
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
