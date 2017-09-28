package main

import (
	"flag"
	"fmt"
	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
)

var (
	host       = flag.String("host", "127.0.0.1", "host")
	serverHost = flag.String("serverhost", "127.0.0.1", "server host")
	namesOnly  = flag.Bool("nameonly", false, "only print packet names instead of full data")
	dumpStack  = flag.Bool("trace", false, "goroutine dump on exit")
	debugMode  = flag.Bool("debug", false, "verbose logging for dev")

	// Port mappings for handling incoming client connections.
	portMappings = map[string]string{
		"11000": "PATCH",
		"11001": "DATA",
		"12000": "LOGIN",
		"12001": "CHARACTER",
		"13000": "SHIPGATE",
		"15000": "SHIP",
		"15001": "BLOCK1",
		"15002": "BLOCK2",
	}

	// Server ports to which data will be forwarded by the proxy.
	serverPortMappings = map[string]string{
		"11000": "11010",
		"11001": "11011",
		"12000": "12010",
		"12001": "12011",

		"13000": "13010",
		"15000": "15010",
		"15001": "15011",
		"15002": "15012",
	}

	// Functionally a boundless unbuffered channel for packets that will be read for logging.
	packetChan = make(chan *Packet, 500)
	// Used for ordered printing of debug messages to stdout.
	debugChan = make(chan string, 100)
)

const displayWidth = 16

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)

	if *dumpStack {
		go func() {
			// Signal handler that will dump goroutines on exit.
			signalChan := make(chan os.Signal)
			signal.Notify(signalChan, os.Kill, os.Interrupt)
			<-signalChan

			stackBuf := make([]byte, 2^16)
			runtime.Stack(stackBuf, true)
			fmt.Println(string(stackBuf))
			os.Exit(1)

		}()
	}

	for port, name := range portMappings {
		proxy := &Proxy{
			serverName: name,
			proxyHost:  *host,
			proxyPort:  port,
			serverHost: *serverHost,
			serverPort: serverPortMappings[port],
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
		log.Printf("Failed to start proxy on %s:%s; error: %s\n",
			proxy.proxyHost, proxy.proxyPort, err.Error())
		os.Exit(2)
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Printf("Failed to start proxy on %s:%s; error: %s\n",
			proxy.proxyHost, proxy.proxyPort, err.Error())
		os.Exit(2)
	}
	defer listener.Close()

	log.Printf("Forwarding %s connections on %s:%s to %s:%s\n", proxy.serverName,
		proxy.proxyHost, proxy.proxyPort, proxy.serverHost, proxy.serverPort)
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Println("Failed to accept connection: " + err.Error())
			continue
		}
		log.Printf("Accepted %s proxy connection on %s:%s\n",
			proxy.serverName, proxy.proxyHost, proxy.proxyPort)

		// Establish a connection with the target PSO server.
		serverConn, err := net.Dial("tcp", proxy.serverHost+":"+proxy.serverPort)
		if err != nil {
			log.Println("Failed to connect to server: " + err.Error())
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
		log.Println("WelcomePacket sent from Server to Client")
		util.PrintPayload(vectorBuf[:bytes], bytes)
		log.Println()

		if err := send(serverInterceptor.OutConn, vectorBuf[:bytes], uint16(bytes)); err != nil {
			log.Println("Failed to forward encryption packet; disconnecting")
			conn.Close()
			serverConn.Close()
		}
	}
}

func (proxy *Proxy) buildCrypts(buf []byte) (*crypto.PSOCrypt, *crypto.PSOCrypt, uint16) {
	var header Header
	util.StructFromBytes(buf, &header)
	if header.Type == 0x02 {
		var welcomePkt PatchWelcomePkt
		util.StructFromBytes(buf, &welcomePkt)
		cCrypt := crypto.NewPCCrypt(welcomePkt.ClientVector)
		sCrypt := crypto.NewPCCrypt(welcomePkt.ServerVector)
		return cCrypt, sCrypt, 4
	} else {
		var welcomePkt WelcomePkt
		util.StructFromBytes(buf, &welcomePkt)
		cCrypt := crypto.NewBBCrypt(welcomePkt.ClientVector)
		sCrypt := crypto.NewBBCrypt(welcomePkt.ServerVector)
		return cCrypt, sCrypt, 8
	}
}

// Handler for any packets intercepted by the proxy. Responsible for sending the packets to
// their intended destination as well as doing any logging we care about.
func consumePackets(packetChan <-chan *Packet) {
	for {
		packet := <-packetChan

		log.Printf("%s packet sent from %s to %s\n", packet.server, packet.fromName, packet.toName)
		name := getPacketName(packet.server, packet.command)
		if name == "" {
			log.Printf("Unknown packet %2x\n", packet.command)
		} else {
			log.Println(name)
		}
		PrintPayload(packet.decryptedData, int(packet.size))
		log.Println()

		debug(fmt.Sprintf("Sending %d bytes from %s to %s",
			packet.size, packet.fromName, packet.toName))
		if err := send(packet.destConn, packet.data, packet.size); err != nil {
			fmt.Printf("Failed to send packet: %s\n", err.Error())
			break
		}
	}
}

func send(conn net.Conn, data []byte, size uint16) error {
	for bytesSent := uint16(0); bytesSent < size; {
		n, err := conn.Write(data[bytesSent:size])
		if err != nil {
			return err
		}
		bytesSent += uint16(n)
	}
	return nil
}

// Print the contents of a packet to stdout in two columns, one for bytes and
// the other for their ascii representation.
func PrintPayload(data []uint8, pktLen int) {
	for rem, offset := pktLen, 0; rem > 0; rem -= displayWidth {
		if rem < displayWidth {
			printPacketLine(data[(pktLen-rem):pktLen], rem, offset)
		} else {
			printPacketLine(data[offset:offset+displayWidth], displayWidth, offset)
		}
		offset += displayWidth
	}
}

// Write one line of data to stdout.
func printPacketLine(data []uint8, length int, offset int) {
	fmt.Printf("(%04X) ", offset)
	// Print our bytes.
	for i, j := 0, 0; i < length; i++ {
		if j == 8 {
			// Visual aid - spacing between groups of 8 bytes.
			j = 0
			fmt.Print("  ")
		}
		fmt.Printf("%02x ", data[i])
		j++
	}
	// Fill in the gap if we don't have enough bytes to fill the line.
	for i := length; i < displayWidth; i++ {
		if i == 8 {
			fmt.Print("  ")
		}
		fmt.Print("   ")
	}
	fmt.Print("    ")
	// Display the print characters as-is, others as periods.
	for i := 0; i < length; i++ {
		c := data[i]
		if strconv.IsPrint(rune(c)) {
			fmt.Printf("%c", data[i])
		} else {
			fmt.Print(".")
		}
	}
	fmt.Println()
}

func logDebugMessages(debugChan <-chan string) {
	for {
		message := <-debugChan
		log.Printf("%s\n", message)
	}
}
