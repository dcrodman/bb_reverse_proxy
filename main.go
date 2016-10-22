package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
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

	dumpStack = flag.Bool("trace", false, "goroutine dump on exit")
)

func main() {
	flag.Parse()
	for s := range serverPortMappings {
		c := serverConn(s)
		c.Close()
	}
	if *dumpStack {
		go interceptKill()
	}
	wg := new(sync.WaitGroup)
	for s, p := range portMappings {
		wg.Add(1)
		go startReceiver(s, *host, p, wg)
	}
	wg.Wait()
}

// Open a connection to a mapped server by name.
func serverConn(serverName string) *net.TCPConn {
	addr, _ := net.ResolveTCPAddr("tcp", *serverHost+":"+serverPortMappings[serverName])
	conn, err := net.DialTCP("tcp", nil, addr)
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
	addr, err := net.ResolveTCPAddr("tcp", host+":"+port)
	if err != nil {
		fmt.Println("Failed to start proxy on %s:%s; error: \n", host, port, err.Error())
		os.Exit(2)
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		fmt.Println("Failed to start proxy on %s:%s; error: \n", host, port, err.Error())
		os.Exit(2)
	}
	fmt.Printf("Forwarding %s connections on %s:%s to %s:%s\n",
		name, host, port, host, serverPortMappings[name])
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			fmt.Println("Failed to accept connection: " + err.Error())
			continue
		}
		sConn := serverConn(name)
		interceptor := &Interceptor{clientConn: conn, serverConn: sConn}
		interceptor.Start()
	}
	listener.Close()
	wg.Done()
}

func interceptKill() {
	signalChan := make(chan os.Signal)
	signal.Notify(signalChan, os.Kill, os.Interrupt)
	<-signalChan
	stackBuf := make([]byte, 10000)
	runtime.Stack(stackBuf, true)
	fmt.Println(string(stackBuf))
	os.Exit(1)
}
