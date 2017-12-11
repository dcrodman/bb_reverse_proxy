package main

import (
	"container/list"
	"flag"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	host       = flag.String("host", "127.0.0.1", "host on which the proxy will listen")
	serverHost = flag.String("serverhost", "127.0.0.1", "host on which the server is listening")
	logFile    = flag.String("file", "", "file to which output will be logged")
	namesOnly  = flag.Bool("nameonly", false, "only print packet names instead of full data")
	debugMode  = flag.Bool("debug", false, "verbose logging for dev")
)

var (
	// All Proxy instances configured to run.
	proxies = list.New()
	// Byte representation of the proxy IP injected into the redirect packet.
	convertedHost [4]byte
	// Used for ordered printing of debug messages to stdout.
	debugChan = make(chan string, 100)
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)

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

	proxies.PushFront(&Proxy{"LOGIN", *host + ":12000", *serverHost + ":12010"})
	proxies.PushFront(&Proxy{"CHARACTER", *host + ":12001", *serverHost + ":12011"})
	proxies.PushFront(&Proxy{"SHIP", *host + ":15000", *serverHost + ":15010"})
	proxies.PushFront(&Proxy{"BLOCK1", *host + ":15001", *serverHost + ":15011"})
	proxies.PushFront(&Proxy{"BLOCK2", *host + ":15002", *serverHost + ":15012"})

	for e := proxies.Front(); e != nil; e = e.Next() {
		go e.Value.(*Proxy).Start()
	}

	if *debugMode {
		go logDebugMessages(debugChan)
	}
	consumePackets(packetChan)

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
