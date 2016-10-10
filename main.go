package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
)

var (
	host         = flag.String("host", "127.0.0.1", "host")
	portMappings = map[string]string{
		"Patch":     "11000",
		"Data":      "11001",
		"Login":     "12000",
		"Character": "12001",
	}

	serverHost         = flag.String("serverhost", "127.0.0.1", "server host")
	serverPortMappings = map[string]string{
		"Patch":     "11010",
		"Data":      "11011",
		"Login":     "12010",
		"Character": "12011",
	}
)

func main() {
	for s := range serverPortMappings {
		c := serverConn(s)
		c.Close()
	}

	wg := new(sync.WaitGroup)
	for s, p := range portMappings {
		wg.Add(1)
		go startReceiver(s, *host, p, wg)
	}
	wg.Wait()
}

// Open a connection to the mapped server
func serverConn(serverName string) net.Conn {
	conn, err := net.Dial("tcp", *serverHost+":"+serverPortMappings[serverName])
	if err != nil {
		fmt.Printf("Server connection failed: %s\n", err.Error())
		os.Exit(1)
	}
	return conn
}

// Open up connections for any clients.
func startReceiver(name, host, port string, wg *sync.WaitGroup) {
	listener, err := net.Listen("tcp", host+":"+port)
	if err != nil {
		fmt.Println("Failed to start proxy on %s:%s; error: \n", host, port, err.Error())
		os.Exit(2)
	}
	fmt.Printf("Opening %s proxy on %s:%s\n", name, host, port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept connection: " + err.Error())
			continue
		}
		conn.Close()
	}
	listener.Close()
	wg.Done()
}
