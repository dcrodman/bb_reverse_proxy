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
		"PATCH":     "11000",
		"DATA":      "11001",
		"LOGIN":     "12000",
		"CHARACTER": "12001",
	}

	serverHost         = flag.String("serverhost", "127.0.0.1", "server host")
	serverPortMappings = map[string]string{
		"PATCH":     "11010",
		"DATA":      "11011",
		"LOGIN":     "12010",
		"CHARACTER": "12011",
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

// Open a connection to a mapped server by name.
func serverConn(serverName string) net.Conn {
	conn, err := net.Dial("tcp", *serverHost+":"+serverPortMappings[serverName])
	if err != nil {
		fmt.Printf("Server connection failed: %s\n", err.Error())
		// TODO: This should only be an exit in the initial check
		os.Exit(1)
	}
	return conn
}

// Start a TCP listener on the specified host:port. When clients connect, create
// a connection to the corresponding server and set up an InterceptService to
// handle the communication between them.
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
		sConn := serverConn(name)
		interceptor := &Interceptor{conn, sConn}
		interceptor.Start()
	}
	listener.Close()
	wg.Done()
}
