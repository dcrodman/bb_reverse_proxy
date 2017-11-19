package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
)

// Proxy
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
		headerStr := "WelcomePacket sent from Server to Client\n"
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
