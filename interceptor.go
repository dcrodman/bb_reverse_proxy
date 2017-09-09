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

var sessionEnded = errors.New("Session ended")

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
		if err == sessionEnded || err == io.EOF {
			fmt.Println("Disconnected " + fromAddr)
			i.InConn.Close()
			i.Partner.Kill()
			break
		} else if err != nil {
			fmt.Printf("Error reading from %s: %s\n", fromAddr, err.Error())
			break
		}

		packet.fromName = i.InName
		packet.toName = i.OutName
		packet.server = i.ServerName

		i.PacketOutputChan <- packet
		err = i.Send(packet.data, packet.size)
		if err != nil {
			fmt.Printf("Disconnecting client (%s)\n", err)
			break
		}
	}
}

func (i *Interceptor) readNextPacket() (*Packet, error) {
	// Just read in the header so we know how much data we're expecting.
	buf := make([]byte, i.HeaderSize)
	err := i.readBytes(buf, i.HeaderSize)
	if err != nil {
		return nil, err
	}

	decryptedBuf := i.decryptData(buf, i.HeaderSize)
	var packetHeader Header
	util.StructFromBytes(decryptedBuf, &packetHeader)

	// Now we read in the rest of the packet and append it to what we have.
	remainingSize := packetHeader.Size - i.HeaderSize
	remBuf := make([]byte, remainingSize)
	err = i.readBytes(remBuf, remainingSize)
	if err != nil {
		return nil, err
	}
	decryptedRemBuf := i.decryptData(remBuf, remainingSize)

	packet := Packet{
		command:       packetHeader.Type,
		size:          packetHeader.Size,
		data:          append(buf, remBuf...),
		decryptedData: append(decryptedBuf, decryptedRemBuf...),
		timestamp:     time.Now(),
	}
	return &packet, err
}

func (i *Interceptor) readBytes(buf []byte, bytesToRead uint16) error {
	for bytesReceived := uint16(0); bytesReceived < bytesToRead; {
		// Timeouts give us an opportunity to check if the connection is dead.
		i.InConn.SetReadDeadline(time.Now().Add(time.Second))
		bytesRead, err := i.InConn.Read(buf[bytesReceived:bytesToRead])

		if err != nil {
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() && i.stop {
				return sessionEnded
			} else if !ok {
				return err
			}
		}
		bytesReceived += uint16(bytesRead)

	}
	return nil
}

func (i *Interceptor) decryptData(buf []byte, size uint16) []byte {
	decryptedBuf := append(make([]byte, 0), buf...)
	i.Crypt.Decrypt(decryptedBuf, uint32(size))
	return decryptedBuf
}

func (i *Interceptor) Send(data []byte, size uint16) error {
	for bytesSent := uint16(0); bytesSent < size; {
		n, err := i.OutConn.Write(data[bytesSent:size])
		if err != nil {
			return err
		}
		bytesSent += uint16(n)
	}
	return nil
}

func (i *Interceptor) Kill() {
	i.stop = true
}
