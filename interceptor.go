package main

import (
	"errors"
	"fmt"
	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
	"io"
	"net"
	"time"
)

var errSessionEnded = errors.New("Session ended")

// Interceptor objects are responsible for reading packets off of the wire for one direction
// of a session. For every connection, there should be one Interceptor for the client->proxy
// side and one for the proxy->server.
type Interceptor struct {
	ServerName string
	InConn     net.Conn
	InName     string
	OutConn    net.Conn
	OutName    string

	Crypt            *crypto.PSOCrypt
	HeaderSize       uint16
	PacketOutputChan chan<- *Packet

	Partner *Interceptor
	stop    bool
}

func (i *Interceptor) Forward() {
	fromAddr := i.InConn.RemoteAddr().String()
	for {
		packet, err := i.readNextPacket()
		if err == errSessionEnded || err == io.EOF {
			break
		} else if err != nil {
			fmt.Printf("Error reading from %s: %s\n", fromAddr, err.Error())
			break
		}

		packet.server = i.ServerName
		packet.fromName = i.InName
		packet.toName = i.OutName
		packet.destConn = i.OutConn

		i.PacketOutputChan <- packet
	}
	fmt.Printf("Closed %s connection on %s (%s)\n", i.InName, fromAddr, i.ServerName)
	i.InConn.Close()
	i.Partner.Kill()
}

func (i *Interceptor) readNextPacket() (*Packet, error) {
	// Just read in the header so we know how much data we're expecting.
	buf := make([]byte, i.HeaderSize)
	debug("Awaiting header from " + i.InName)
	err := i.readBytes(buf, i.HeaderSize)
	if err != nil {
		return nil, err
	}

	decryptedBuf := i.decryptData(buf, i.HeaderSize)
	var packetHeader Header
	util.StructFromBytes(decryptedBuf, &packetHeader)

	// Now we read in the rest of the packet and append it to what we have.
	remainingSize := packetHeader.Size - i.HeaderSize
	remainingSize += remainingSize % i.HeaderSize

	remBuf := make([]byte, remainingSize)
	debug("Awaiting rest of packet from " + i.InName)
	err = i.readBytes(remBuf, remainingSize)
	if err != nil {
		return nil, err
	}
	decryptedRemBuf := i.decryptData(remBuf, remainingSize)

	packet := Packet{
		command:       packetHeader.Type,
		size:          remainingSize + i.HeaderSize,
		data:          append(buf, remBuf...),
		decryptedData: append(decryptedBuf, decryptedRemBuf...),
		timestamp:     time.Now(),
	}
	return &packet, err
}

func (i *Interceptor) readBytes(buf []byte, bytesToRead uint16) error {
	debug(fmt.Sprintf("%d total bytes to read from %s", bytesToRead, i.InName))
	for bytesReceived := uint16(0); bytesReceived < bytesToRead; {
		// Timeouts give us an opportunity to check if the connection is dead.
		i.InConn.SetReadDeadline(time.Now().Add(time.Second))
		bytesRead, err := i.InConn.Read(buf[bytesReceived:bytesToRead])

		if err != nil {
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() && i.stop {
				return errSessionEnded
			} else if !ok {
				return err
			}
		}
		debug(fmt.Sprintf("%d bytes of %d read from %s", bytesRead, bytesToRead, i.InName))
		bytesReceived += uint16(bytesRead)
	}
	return nil
}

func (i *Interceptor) decryptData(buf []byte, size uint16) []byte {
	decryptedBuf := append(make([]byte, 0), buf...)
	i.Crypt.Decrypt(decryptedBuf, uint32(size))
	return decryptedBuf
}

func (i *Interceptor) Kill() {
	i.stop = true
}
