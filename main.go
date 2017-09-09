package main

import (
	"flag"
	"fmt"
	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
)

var (
	host       = flag.String("host", "127.0.0.1", "host")
	serverHost = flag.String("serverhost", "127.0.0.1", "server host")
	dumpStack  = flag.Bool("trace", false, "goroutine dump on exit")
	namesOnly  = flag.Bool("nameonly", false, "only print packet names instead of full data")

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
)

// Functionally a boundless unbuffered channel for packets that will be read for logging.
var packetChan = make(chan *Packet, 500)

func main() {
	flag.Parse()
	if *dumpStack {
		go func() {
			// Signal handler that will dump goroutines on exit.
			signalChan := make(chan os.Signal)
			signal.Notify(signalChan, os.Kill, os.Interrupt)
			<-signalChan

			stackBuf := make([]byte, 10000)
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

	wg := new(sync.WaitGroup)
	wg.Add(1)
	wg.Wait()
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
		os.Exit(2)
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		fmt.Printf("Failed to start proxy on %s:%s; error: %s\n",
			proxy.proxyHost, proxy.proxyPort, err.Error())
		os.Exit(2)
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
		fmt.Printf("Accepted %s proxy connection on %s:%s\n",
			proxy.serverName, proxy.proxyHost, proxy.proxyPort)

		// Establish a connection with the target PSO server.
		serverConn, err := net.Dial("tcp", proxy.serverHost+":"+proxy.serverPort)
		if err != nil {
			fmt.Println("Failed to connect to server: " + err.Error())
			conn.Close()
			continue
		}
		fmt.Printf("Opened %s server connection to %s:%s\n",
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
		fmt.Println("WelcomePacket sent from Server to Client")
		util.PrintPayload(vectorBuf[:bytes], bytes)
		fmt.Println()

		err = serverInterceptor.Send(vectorBuf[:bytes], uint16(bytes))
		if err != nil {
			fmt.Println("Failed to forward encryption packet; disconnecting")
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

func consumePackets(packetChan chan *Packet) {
	for {
		packet := <-packetChan
		stamp := packet.timestamp.Format("15:04:05.000")

		fmt.Printf("[%v] %s packet sent from %s to %s\n", stamp,
			packet.server, packet.toName, packet.fromName)
		name := getPacketName(packet.server, packet.command)
		if name == "" {
			fmt.Printf("Unknown packet %2x\n", packet.command)
		} else {
			fmt.Println(name)
		}
		util.PrintPayload(packet.decryptedData, int(packet.size))
		fmt.Println()
	}
}
