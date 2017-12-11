package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dcrodman/archon/util"
	crypto "github.com/dcrodman/bb_reverse_proxy/encryption"
)

const headerSize = 8

var errSessionEnded = errors.New("Session ended")

// Interceptor objects are responsible for reading packets off of the wire for one direction
// of a session. For every connection, there should be one Interceptor for the client->proxy
// side and one for the proxy->server.
type Interceptor struct {
	ServerName string
	Name       string
	RecvConn   net.Conn
	RecvCrypt  *crypto.PSOCrypt
	SendConn   net.Conn
	Partner    *Interceptor
	stop       int32
}

// Start runs the packet processing loop for the interceptor's connection.
func (i *Interceptor) Start() {
	for {
		packet, err := i.readNextPacket()
		if err == errSessionEnded || err == io.EOF {
			break
		} else if err != nil {
			fmt.Printf("Error reading from %s: %s\n", i.RecvConn.RemoteAddr().String(), err.Error())
			break
		}

		i.rewriteRedirect(packet)

		packet.sendFunc = func() {
			debug(fmt.Sprintf("Sending %d bytes to %s", packet.size, packet.fromName))
			if err := i.send(packet.data, packet.size); err != nil {
				fmt.Printf("Failed to send packet: %s\n", err.Error())
			}
		}
		packetChan <- packet
	}

	i.RecvConn.Close()
	i.Partner.Kill()
	log.Printf("Closed %s connection on %s (%s)\n\n",
		i.Name, i.RecvConn.RemoteAddr().String(), i.ServerName)
}

func (i *Interceptor) readNextPacket() (*PacketMsg, error) {
	// Just read in the header so we know how much data we're expecting.
	buf := make([]byte, headerSize)
	debug("Awaiting header from " + i.Name)
	err := i.readBytes(buf, headerSize)
	if err != nil {
		return nil, err
	}

	decryptedBuf := i.decryptData(buf, headerSize)
	var packetHeader Header
	util.StructFromBytes(decryptedBuf, &packetHeader)

	// Now we read in the rest of the packet and append it to what we have.
	remainingSize := packetHeader.Size - headerSize
	remainingSize += remainingSize % headerSize

	remBuf := make([]byte, remainingSize)
	debug("Awaiting rest of packet from " + i.Name)
	err = i.readBytes(remBuf, remainingSize)
	if err != nil {
		return nil, err
	}
	decryptedRemBuf := i.decryptData(remBuf, remainingSize)

	packet := PacketMsg{
		command:       packetHeader.Type,
		size:          remainingSize + headerSize,
		data:          append(buf, remBuf...),
		decryptedData: append(decryptedBuf, decryptedRemBuf...),
		timestamp:     time.Now(),
		server:        i.ServerName,
		fromName:      i.Name,
	}
	return &packet, err
}

func (i *Interceptor) readBytes(buf []byte, bytesToRead uint16) error {
	debug(fmt.Sprintf("%d total bytes to read from %s", bytesToRead, i.Name))
	for bytesReceived := uint16(0); bytesReceived < bytesToRead; {
		// Timeouts give us an opportunity to check if the connection is dead.
		i.RecvConn.SetReadDeadline(time.Now().Add(time.Second))
		bytesRead, err := i.RecvConn.Read(buf[bytesReceived:bytesToRead])

		if err != nil {
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() && atomic.LoadInt32(&i.stop) > 0 {
				return errSessionEnded
			} else if !ok {
				return err
			}
		}
		debug(fmt.Sprintf("%d bytes of %d read from %s", bytesRead, bytesToRead, i.Name))
		bytesReceived += uint16(bytesRead)
	}
	return nil
}

func (i *Interceptor) decryptData(buf []byte, size uint16) []byte {
	decryptedBuf := append(make([]byte, 0), buf...)
	i.RecvCrypt.Decrypt(decryptedBuf, uint32(size))
	return decryptedBuf
}

// Rewrite the connection parameters to point back at the proxy.
func (i *Interceptor) rewriteRedirect(packet *PacketMsg) {
	var packetStruct interface{}
	var port uint16

	if packet.command == RedirectType {
		var redirectPkt RedirectPacket
		util.StructFromBytes(packet.decryptedData, &redirectPkt)

		copy(redirectPkt.IPAddr[:], convertedHost[:])
		redirectPkt.Port = i.getProxyPort(redirectPkt.Port)
		packetStruct = redirectPkt
	}

	if packetStruct != nil {
		rewrittenBytes, _ := util.BytesFromStruct(packetStruct)
		i.RecvCrypt.Encrypt(rewrittenBytes, uint32(packet.size))
		copy(packet.data, rewrittenBytes)
		log.Printf("Rewrote redirect packet IP to %s:%d\n\n", *host, port)
	}
}

// Takes the port provided by the server for a redirect and returns the corresponding
// proxy port set up to capture traffic.
func (i *Interceptor) getProxyPort(serverPort uint16) uint16 {
	convertedPort := strconv.FormatUint(uint64(serverPort), 10)
	for e := proxies.Front(); e != nil; e = e.Next() {
		proxy := e.Value.(*Proxy)
		if strings.HasSuffix(proxy.remoteHost, convertedPort) {
			splitHost := strings.Split(proxy.host, ":")
			conv, _ := strconv.ParseUint(splitHost[len(splitHost)-1], 10, 16)
			return uint16(conv)
		}
	}
	fmt.Printf("WARN: Port mappings misconfigured; no proxy port for %d\n", serverPort)
	return serverPort
}

func (i *Interceptor) send(data []byte, size uint16) error {
	for bytesSent := uint16(0); bytesSent < size; {
		n, err := i.SendConn.Write(data[bytesSent:size])
		if err != nil {
			return err
		}
		bytesSent += uint16(n)
	}
	return nil
}

// Kill will cause the Interceptor to stop processing packets and return from Start().
func (i *Interceptor) Kill() {
	atomic.AddInt32(&i.stop, 1)
}
