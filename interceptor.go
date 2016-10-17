package main

import (
	"fmt"
	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
	"net"
	"sync"
)

type Header struct {
	Size uint16
	Type uint16
}

// Welcome packet with encryption vectors sent to the client upon initial connection.
type PatchWelcomePkt struct {
	Header
	Copyright    [44]byte
	Padding      [20]byte
	ServerVector [4]byte
	ClientVector [4]byte
}

// Welcome packet with encryption vectors sent to the client upon initial connection.
type WelcomePkt struct {
	Header
	Flags        uint32
	Copyright    [96]byte
	ServerVector [48]byte
	ClientVector [48]byte
}

type Interceptor struct {
	clientConn *net.TCPConn
	serverConn *net.TCPConn
}

// Set up the bi-directional communication and intercept hook for
// packets traveling between the client and target server.
func (i *Interceptor) Start() {
	go func() {
		defer func() {
			i.clientConn.Close()
			i.serverConn.Close()
		}()
		// Intercept the encryption vectors
		var headerSize uint16
		var clientCrypt, serverCrypt *crypto.PSOCrypt
		buf := make([]byte, 256)
		bytes, _ := i.serverConn.Read(buf)
		clientCrypt, serverCrypt, headerSize = i.buildCrypts(buf)

		// Client uses the client vector to send data, the server uses the server
		// one. In order to reuse the packet functionality from Client, we can
		// just reverse them and the cryptographic part should work.
		client := NewClient(i.clientConn, headerSize, clientCrypt, serverCrypt)
		server := NewClient(i.serverConn, headerSize, serverCrypt, clientCrypt)
		fmt.Printf("From %s:%s (server)\n", server.ipAddr, server.port)
		util.PrintPayload(buf[:bytes], bytes)
		fmt.Println()
		client.Send(buf[:bytes])

		wg := new(sync.WaitGroup)
		wg.Add(2)
		go func() {
			for {
				serverBuf := make([]byte, 1024)
				bytes, err := i.serverConn.Read(serverBuf)
				if err != nil {
					fmt.Println("Error reading from server" + err.Error())
					break
				}
				logPacketBuf(serverBuf, bytes, "server")
				i.clientConn.Write(serverBuf[:bytes])
			}
		}()
		go func() {
			for {
				clientBuf := make([]byte, 1024)
				bytes, err := i.clientConn.Read(clientBuf)
				if err != nil {
					fmt.Println("Error reading from client: " + err.Error())
					break
				}
				logPacketBuf(clientBuf, bytes, "client")
				i.serverConn.Write(clientBuf[:bytes])
			}
		}()
		wg.Wait()
	}()
}

func (interceptor *Interceptor) buildCrypts(buf []byte) (c, s *crypto.PSOCrypt, hdrSize uint16) {
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

func logPacket(c *Client, msg string) {
	fmt.Printf("From %s:%s (%s)\n", c.ipAddr, c.port, msg)
	util.PrintPayload(c.decryptedBuffer, int(c.packetSize))
	fmt.Println()
}

func logPacketBuf(buf []byte, l int, msg string) {
	fmt.Printf("%s\n", msg)
	util.PrintPayload(buf, int(l))
	fmt.Println()
}
