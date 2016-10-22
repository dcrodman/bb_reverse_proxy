package main

import (
	"errors"
	"fmt"
	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

var SessionEnded = errors.New("Session ended")

type Packet struct {
	size          uint16
	data          []byte
	decryptedData []byte
}

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
	stop       bool

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
		clientCrypt, serverCrypt, hSize := i.buildCrypts(vectorBuf)

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

func (i Interceptor) buildCrypts(buf []byte) (c, s *crypto.PSOCrypt, hdrSize uint16) {
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

func (i *Interceptor) forward(from, to *net.TCPConn, fromName string) {
	toAddr := to.RemoteAddr().String()
	for {
		packet, err := i.readNextPacket(from)
		if err == SessionEnded {
			break
		} else if err == io.EOF {
			fmt.Println(fromName + " has disconnected")
			break
		} else if err != nil {
			fmt.Printf("Error reading from %s: %s\n", toAddr, err.Error())
			break
		}
		fmt.Printf("Sending to %s from %s\n", toAddr, fromName)
		util.PrintPayload(packet.decryptedData, int(packet.size))
		fmt.Println()

		to.Write(packet.data)
	}
	i.stop = true
	i.wg.Done()
}

func (i *Interceptor) readNextPacket(from *net.TCPConn) (*Packet, error) {
	headerSize := int(i.headerSize)
	buf, decrBuf, err := i.readDecrypted(from, headerSize)
	if err != nil {
		return nil, err
	}
	var packetHeader Header
	util.StructFromBytes(decrBuf, &packetHeader)

	packetSize := int(packetHeader.Size)
	if packetSize > len(buf) {
		// Make sure the packet sizes are always a multiple of the header size.
		packetSize += (packetSize % headerSize)
		remBuf, remDecrBuf, err := i.readDecrypted(from, packetSize-headerSize)
		if err != nil {
			return nil, err
		}
		buf = append(buf, remBuf...)
		decrBuf = append(decrBuf, remDecrBuf...)
	}
	packet := Packet{data: buf, decryptedData: decrBuf, size: uint16(packetSize)}
	return &packet, err
}

func (i *Interceptor) readDecrypted(from *net.TCPConn, size int) ([]byte, []byte, error) {
	buf := make([]byte, size)
	err := i.readBytes(from, size, buf)
	if err != nil {
		return nil, nil, err
	}
	decryptedBuf := append(make([]byte, 0), buf...)
	crypt := i.crypts[from.RemoteAddr().String()]
	crypt.Decrypt(decryptedBuf, uint32(size))

	return buf, decryptedBuf, err
}

func (i *Interceptor) readBytes(from *net.TCPConn, bytes int, dest []byte) error {
	bytesReceived := 0
	for bytesReceived < bytes {
		from.SetReadDeadline(time.Now().Add(time.Second))
		bytesRead, err := from.Read(dest[bytesReceived:bytes])
		if err != nil && strings.Contains(err.Error(), "timeout") {
			// Timeouts give us an opportunity to check if the connection is dead.
			if i.stop {
				return SessionEnded
			}
		} else if err != nil {
			return err
		}
		bytesReceived += bytesRead
	}
	return nil
}
