package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
)

// Proxy objects await connections on their defined ports and spin off Interceptor
// instances to handle the traffic.
type Proxy struct {
	serverName string
	host       string
	remoteHost string
}

// Start a TCP listener on the specified host:port. When clients connect, create
// a connection to the corresponding server and set up an InterceptService to
// handle the communication between them.
func (proxy *Proxy) Start() {
	fmt.Printf("Forwarding %s connections on %s to %s\n", proxy.serverName, proxy.host, proxy.remoteHost)
	listener := proxy.openSocket()
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			fmt.Println("Failed to accept connection: " + err.Error())
			continue
		}
		log.Printf("Accepted %s proxy connection on %s\n", proxy.serverName, proxy.host)

		// Establish a connection with the target PSO server.
		serverConn, err := net.Dial("tcp", proxy.remoteHost)
		if err != nil {
			fmt.Println("Failed to connect to server: " + err.Error())
			conn.Close()
			continue
		}
		log.Printf("Opened %s server connection to %s\n", proxy.serverName, proxy.remoteHost)

		// Intercept the encryption vectors so that we can decrypt traffic.
		vectorBuf := make([]byte, 256)
		bytes, _ := serverConn.Read(vectorBuf)
		clientCrypt, serverCrypt := proxy.buildCrypts(vectorBuf)

		// Decrypt and forward any data sent from the client.
		clientInterceptor := &Interceptor{
			ServerName: proxy.serverName,
			Name:       "Client",
			RecvConn:   conn,
			RecvCrypt:  clientCrypt,
			SendConn:   serverConn,
		}

		// Decrypt and forward any data sent from the server.
		serverInterceptor := &Interceptor{
			ServerName: proxy.serverName,
			Name:       "Server",
			RecvConn:   serverConn,
			RecvCrypt:  serverCrypt,
			SendConn:   conn,
		}

		// Give the two a clean way to stop each other when the other disconnects.
		clientInterceptor.Partner = serverInterceptor
		serverInterceptor.Partner = clientInterceptor

		go clientInterceptor.Start()
		go serverInterceptor.Start()

		// Send the encryption packet on to the client since we pulled it off the socket.
		welcomePacket := &PacketMsg{
			size:          uint16(bytes),
			command:       uint16(vectorBuf[0x02]),
			decryptedData: vectorBuf,
			server:        proxy.serverName,
		}
		log.Println(formatPayload(welcomePacket, fmt.Sprintf("%s Server packet\n", proxy.serverName)))

		if err := serverInterceptor.send(vectorBuf[:bytes], uint16(bytes)); err != nil {
			fmt.Println("Failed to forward encryption packet; disconnecting")
			conn.Close()
			serverConn.Close()
		}
	}
}

func (proxy *Proxy) openSocket() *net.TCPListener {
	addr, err := net.ResolveTCPAddr("tcp", proxy.host)
	if err != nil {
		fmt.Printf("Failed to start proxy on %s; error: %s\n", proxy.host, err.Error())
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		fmt.Printf("Failed to start proxy on %s; error: %s\n", proxy.host, err.Error())
		os.Exit(1)
	}
	return listener
}

func (proxy *Proxy) buildCrypts(buf []byte) (*crypto.PSOCrypt, *crypto.PSOCrypt) {
	var header Header
	util.StructFromBytes(buf, &header)

	var welcomePkt WelcomePkt
	util.StructFromBytes(buf, &welcomePkt)
	cCrypt := crypto.NewBBCrypt(welcomePkt.ClientVector)
	sCrypt := crypto.NewBBCrypt(welcomePkt.ServerVector)
	return cCrypt, sCrypt
}
