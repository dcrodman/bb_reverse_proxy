package main

import (
	"flag"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	// Port mappings for handling incoming client connections.
	portMappings = map[uint16]string{
		//11000: "PATCH",
		//11001: "DATA",
		12000: "LOGIN",
		12001: "CHARACTER",
		13000: "SHIPGATE",
		15000: "SHIP",
		15001: "BLOCK1",
		15002: "BLOCK2",
	}

	// Server ports to which data will be forwarded by the proxy.
	serverPortMappings = map[uint16]uint16{
		//11000: 11010,
		//11001: 11011,
		12000: 12000,
		12001: 12001,
		13000: 13000,
		15000: 15000,
		15001: 15001,
		15002: 15002,
	}
)

var (
	host          = flag.String("host", "127.0.0.1", "host on which the proxy will listen")
	serverHost    = flag.String("serverhost", "127.0.0.1", "host on which the server is listening")
	logFile       = flag.String("file", "", "file to which output will be logged")
	skipTimestamp = flag.Bool("notime", false, "don't log timestamps")
	namesOnly     = flag.Bool("nameonly", false, "only print packet names instead of full data")
	debugMode     = flag.Bool("debug", false, "verbose logging for dev")
)

var (
	// Byte representation of the proxy IP injected into the redirect packet.
	convertedHost [4]byte
	// Functionally a boundless unbuffered channel for packets that will be read for logging.
	packetChan = make(chan *Packet, 500)
	// Used for ordered printing of debug messages to stdout.
	debugChan = make(chan string, 100)
)

func main() {
	flag.Parse()
	if !*skipTimestamp {
		log.SetFlags(log.Ltime)
	}

	if *logFile != "" {
		file, err := os.OpenFile(*logFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.ModePerm)
		if err != nil {
			log.Fatalf("Unable to open log file: %s", err.Error())
		}
		log.SetOutput(file)
	}

	// Pre-convert the host for redirect packets.
	parts := strings.Split(*host, ".")
	for i := 0; i < 4; i++ {
		tmp, _ := strconv.ParseUint(parts[i], 10, 8)
		convertedHost[i] = uint8(tmp)
	}

	// Start all of our proxies on the specified ports.
	for port, name := range portMappings {
		proxy := &Proxy{
			serverName: name,
			proxyHost:  *host,
			proxyPort:  strconv.FormatUint(uint64(port), 10),
			serverHost: *serverHost,
			serverPort: strconv.FormatUint(uint64(serverPortMappings[port]), 10),
		}
		go proxy.Start()
	}

	go consumePackets(packetChan)
	if *debugMode {
		go logDebugMessages(debugChan)
	}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	wg.Wait()
}

func debug(message string) {
	if *debugMode {
		debugChan <- message
	}
}

func logDebugMessages(debugChan <-chan string) {
	for {
		message := <-debugChan
		log.Printf("%s\n", message)
	}
}
