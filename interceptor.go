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

type PatchWelcomePkt struct {
	Header
	Copyright    [44]byte
	Padding      [20]byte
	ServerVector [4]byte
	ClientVector [4]byte
}

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
	wg         sync.WaitGroup

	headerSize uint16
	crypts     map[string]*crypto.PSOCrypt
}

// Set up the bi-directional communication and intercept hook for
// packets traveling between the client and target server.
func (i *Interceptor) Start() {
	go func() {
		defer func() {
			i.clientConn.Close()
			i.serverConn.Close()
		}()
		clientAddr := i.clientConn.RemoteAddr().String()
		serverAddr := i.serverConn.RemoteAddr().String()

		// Intercept the encryption vectors so that we can decrypt traffic.
		vectorBuf := make([]byte, 256)
		bytes, _ := i.serverConn.Read(vectorBuf)
		clientCrypt, serverCrypt, hSize := buildCrypts(vectorBuf)

		i.headerSize = hSize
		i.crypts = make(map[string]*crypto.PSOCrypt, 2)
		i.crypts[clientAddr] = clientCrypt
		i.crypts[serverAddr] = serverCrypt

		fmt.Printf("Sending to %s from server\n", clientAddr)
		util.PrintPayload(vectorBuf[:bytes], bytes)
		fmt.Println()
		i.clientConn.Write(vectorBuf[:bytes])

		i.wg.Add(2)
		go i.forward(i.clientConn, i.serverConn, "client")
		go i.forward(i.serverConn, i.clientConn, "server")
		i.wg.Wait()
	}()
}

// Pipe the connection data read from one connection to the other, decrypting
// and logging it before sending it along.
func (i *Interceptor) forward(from, to *net.TCPConn, fromName string) {
	toAddr := to.RemoteAddr().String()
	crypt := i.crypts[from.RemoteAddr().String()]
	for {
		buf := make([]byte, 65535)
		bytes, err := from.Read(buf)
		if err != nil {
			fmt.Printf("Error reading from %s: %s", toAddr, err.Error())
			break
		}
		decryptedBuf := make([]byte, bytes)
		copy(decryptedBuf, buf)
		crypt.Decrypt(decryptedBuf, uint32(bytes))

		fmt.Printf("Sending to %s from %s\n", toAddr, fromName)
		util.PrintPayload(decryptedBuf, int(bytes))
		fmt.Println()

		to.Write(buf[:bytes])
	}
	i.wg.Done()
}

func buildCrypts(buf []byte) (c, s *crypto.PSOCrypt, hdrSize uint16) {
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
