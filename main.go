package main

import (
	"flag"
	"fmt"
	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
	"log"
	"net"
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
		12000: 12010,
		12001: 12011,
		13000: 13010,
		15000: 15010,
		15001: 15011,
		15002: 15012,
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

type Proxy struct {
	serverName string
	proxyHost  string
	proxyPort  string
	serverHost string
	serverPort string
}

// Start a TCP listener on the specified host:port. When clients connect, create
// a connection to the corresponding server and set up an InterceptService to
// handle the communication between them.
func (proxy *Proxy) Start() {
	addr, err := net.ResolveTCPAddr("tcp", proxy.proxyHost+":"+proxy.proxyPort)
	if err != nil {
		fmt.Printf("Failed to start proxy on %s:%s; error: %s\n",
			proxy.proxyHost, proxy.proxyPort, err.Error())
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		fmt.Printf("Failed to start proxy on %s:%s; error: %s\n",
			proxy.proxyHost, proxy.proxyPort, err.Error())
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("Forwarding %s connections on %s:%s to %s:%s\n", proxy.serverName,
		proxy.proxyHost, proxy.proxyPort, proxy.serverHost, proxy.serverPort)
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			fmt.Println("Failed to accept connection: " + err.Error())
			continue
		}
		log.Printf("Accepted %s proxy connection on %s:%s\n",
			proxy.serverName, proxy.proxyHost, proxy.proxyPort)

		// Establish a connection with the target PSO server.
		serverConn, err := net.Dial("tcp", proxy.serverHost+":"+proxy.serverPort)
		if err != nil {
			fmt.Println("Failed to connect to server: " + err.Error())
			conn.Close()
			continue
		}
		log.Printf("Opened %s server connection to %s:%s\n",
			proxy.serverName, proxy.serverHost, proxy.serverPort)

		// Intercept the encryption vectors so that we can decrypt traffic.
		vectorBuf := make([]byte, 256)
		bytes, _ := serverConn.Read(vectorBuf)
		clientCrypt, serverCrypt, headerSize := proxy.buildCrypts(vectorBuf)

		// Decrypt and forward any data sent from the client.
		clientInterceptor := &Interceptor{
			ServerName:       proxy.serverName,
			InName:           "Client",
			InConn:           conn,
			OutName:          "Server",
			OutConn:          serverConn,
			Crypt:            clientCrypt,
			HeaderSize:       headerSize,
			PacketOutputChan: packetChan,
		}

		// Decrypt and forward any data sent from the server.
		serverInterceptor := &Interceptor{
			ServerName:       proxy.serverName,
			InName:           "Server",
			InConn:           serverConn,
			OutName:          "Client",
			OutConn:          conn,
			Crypt:            serverCrypt,
			HeaderSize:       headerSize,
			PacketOutputChan: packetChan,
		}

		// Give the two a clean way to stop each other when the other disconnects.
		clientInterceptor.Partner = serverInterceptor
		serverInterceptor.Partner = clientInterceptor

		go clientInterceptor.Forward()
		go serverInterceptor.Forward()

		// Send the encryption packet on to the client since we pulled it off the socket.
		welcomePacket := &Packet{
			size:          uint16(bytes),
			command:       uint16(vectorBuf[0x02] >> 1),
			decryptedData: vectorBuf,
			server:        proxy.serverName,
		}
		headerStr := "WelcomePacket sent from Server to Client"
		log.Println(formatPayload(welcomePacket, headerStr))

		if err := send(serverInterceptor.OutConn, vectorBuf[:bytes], uint16(bytes)); err != nil {
			fmt.Println("Failed to forward encryption packet; disconnecting")
			conn.Close()
			serverConn.Close()
		}
	}
}

func (proxy *Proxy) buildCrypts(buf []byte) (*crypto.PSOCrypt, *crypto.PSOCrypt, uint16) {
	var header Header
	util.StructFromBytes(buf, &header)
	// if header.Type == 0x02 {
	// 	var welcomePkt PatchWelcomePkt
	// 	util.StructFromBytes(buf, &welcomePkt)
	// 	cCrypt := crypto.NewPCCrypt(welcomePkt.ClientVector)
	// 	sCrypt := crypto.NewPCCrypt(welcomePkt.ServerVector)
	// 	return cCrypt, sCrypt, 4
	// } else {
	var welcomePkt WelcomePkt
	util.StructFromBytes(buf, &welcomePkt)
	cCrypt := crypto.NewBBCrypt(welcomePkt.ClientVector)
	sCrypt := crypto.NewBBCrypt(welcomePkt.ServerVector)
	return cCrypt, sCrypt, 8
	//}
}
