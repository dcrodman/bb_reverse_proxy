package main

import (
	"fmt"
	"net"
	"sync"
)

const (
	PatchWelcomeType = 0x02
	LoginWelcomeType = 0x03
)

// Welcome packet with encryption vectors sent to the client upon initial connection.
type PatchWelcomePkt struct {
	Size         uint16
	Type         uint16
	Copyright    [44]byte
	Padding      [20]byte
	ServerVector [4]byte
	ClientVector [4]byte
}

// Welcome packet with encryption vectors sent to the client upon initial connection.
type WelcomePkt struct {
	Size         uint16
	Type         uint16
	Flags        uint32
	Copyright    [96]byte
	ServerVector [48]byte
	ClientVector [48]byte
}

type Interceptor struct {
	client net.Conn
	server net.Conn
}

// Set up the bi-directional communication and intercept hook for
// packets traveling between the client and target server.
func (interceptor *Interceptor) Start() {
	go func() {
		defer func() {
			interceptor.client.Close()
			interceptor.server.Close()
		}()
		wg := new(sync.WaitGroup)
		wg.Add(2)
		go interceptor.forward(interceptor.client, interceptor.server, wg)
		go interceptor.forward(interceptor.server, interceptor.client, wg)
		wg.Wait()
	}()
}

func (interceptor *Interceptor) forward(from, to net.Conn, wg *sync.WaitGroup) {
	// for {
	fmt.Println("Forward from " + from.RemoteAddr().String() +
		" to " + to.RemoteAddr().String())
	// }
	wg.Done()
}
