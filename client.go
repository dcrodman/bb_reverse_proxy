/*
* Archon PSO Server
* Copyright (C) 2014 Andrew Rodman
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ---------------------------------------------------------------------
* Client definition for generic handling of connections.
 */
package main

import (
	"container/list"
	"errors"
	"fmt"
	crypto "github.com/dcrodman/archon/encryption"
	"github.com/dcrodman/archon/util"
	"io"
	"net"
	"strings"
	"sync"
)

// Client struct intended to be included as part of the client definitions
// in each of the servers. This struct wraps the connection handling logic
// used by Process() below to handle receiving packets.
type Client struct {
	conn   *net.TCPConn
	ipAddr string
	port   string

	hdrSize    uint16
	recvSize   int
	packetSize uint16
	buffer     []byte

	clientCrypt *crypto.PSOCrypt
	serverCrypt *crypto.PSOCrypt

	guildcard uint32
	teamId    uint32
	isGm      bool

	gcData     []byte
	gcDataSize uint16
	flag       uint32
}

func NewClient(conn *net.TCPConn, hdrSize uint16, cCrypt, sCrypt *crypto.PSOCrypt) *Client {
	addr := strings.Split(conn.RemoteAddr().String(), ":")
	c := &Client{
		conn:        conn,
		ipAddr:      addr[0],
		port:        addr[1],
		hdrSize:     hdrSize,
		clientCrypt: cCrypt,
		serverCrypt: sCrypt,
		buffer:      make([]byte, 512),
	}
	return c
}

func (c *Client) IPAddr() string { return c.ipAddr }

func (c *Client) ClientVector() []uint8 { return c.clientCrypt.Vector }

func (c *Client) ServerVector() []uint8 { return c.serverCrypt.Vector }

func (c *Client) Data() []byte { return c.buffer }

func (c *Client) Close() { c.conn.Close() }

func (c *Client) Send(data []byte) error {
	_, err := c.conn.Write(data)
	return err
}

func (c *Client) Encrypt(data []byte, size uint32) {
	c.serverCrypt.Encrypt(data, size)
}

func (c *Client) Decrypt(data []byte, size uint32) {
	c.clientCrypt.Decrypt(data, size)
}

func (c *Client) Process() error {
	// Extra bytes left in the buffer will just be ignored.
	c.recvSize = 0
	c.packetSize = 0
	hdrint := int(c.hdrSize)

	// Wait for the packet header.
	for c.recvSize < hdrint {
		bytes, err := c.conn.Read(c.buffer[c.recvSize:c.hdrSize])
		if bytes == 0 || err == io.EOF {
			// The client disconnected, we're done.
			return err
		} else if err != nil {
			fmt.Println("Sockt error")
			// Socket error, nothing we can do now.
			return errors.New("Socket Error (" + c.ipAddr + ") " + err.Error())
		}
		c.recvSize += bytes

		if c.recvSize >= hdrint {
			// We have our header; decrypt it.
			c.Decrypt(c.buffer[:c.hdrSize], uint32(c.hdrSize))
			c.packetSize, err = util.GetPacketSize(c.buffer[:2])
			if err != nil {
				// Something is seriously wrong if this causes an error. Bail.
				panic(err.Error())
			}
			// PSO likes to occasionally send us packets that are longer than their declared
			// size, but are always a multiple of the length of the packet header. Adjust the
			// expected length just in case in order to avoid leaving stray bytes in the buffer.
			for c.packetSize%c.hdrSize != 0 {
				c.packetSize++
			}
		}
	}
	pktSize := int(c.packetSize)

	// Grow the client's receive buffer if they send us a packet bigger than its current capacity.
	if pktSize > cap(c.buffer) {
		newSize := pktSize + len(c.buffer)
		newBuf := make([]byte, newSize)
		copy(newBuf, c.buffer)
		c.buffer = newBuf
	}

	// Read in the rest of the packet.
	for c.recvSize < pktSize {
		remaining := pktSize - c.recvSize
		bytes, err := c.conn.Read(c.buffer[c.recvSize : c.recvSize+remaining])
		if err != nil {
			return errors.New("Socket Error (" + c.ipAddr + ") " + err.Error())
		}
		c.recvSize += bytes
	}

	// We have the whole thing; decrypt the rest of it.
	if c.packetSize > c.hdrSize {
		c.Decrypt(c.buffer[c.hdrSize:c.packetSize], uint32(c.packetSize-c.hdrSize))
	}
	return nil
}

// Synchronized list for maintaining a list of connected clients.
type ConnList struct {
	clientList *list.List
	size       int
	sync.RWMutex
}

func NewClientList() *ConnList {
	return &ConnList{clientList: list.New()}
}

// Appends a client to the end of the connection list.
func (cl *ConnList) Add(c *Client) {
	cl.Lock()
	cl.clientList.PushBack(c)
	cl.size++
	cl.Unlock()
}

// Returns true if the list has a Client matching the IP address of c.
// Note that this comparison is by IP address, not element value.
func (cl *ConnList) Has(c *Client) bool {
	found := false
	clAddr := c.IPAddr()
	cl.RLock()
	for client := cl.clientList.Front(); client != nil; client = client.Next() {
		if c.IPAddr() == clAddr {
			found = true
			break
		}
	}
	cl.RUnlock()
	return found
}

func (cl *ConnList) Remove(c *Client) {
	cl.Lock()
	for client := cl.clientList.Front(); client != nil; client = client.Next() {
		if client.Value == c {
			cl.clientList.Remove(client)
			cl.size--
			break
		}
	}
	cl.Unlock()
}

func (cl *ConnList) Count() int {
	cl.RLock()
	length := cl.size
	cl.RUnlock()
	return length
}
