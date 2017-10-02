package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
)

const displayWidth = 16

// Handler for any packets intercepted by the proxy. Responsible for sending the packets to
// their intended destination as well as doing any logging we care about.
func consumePackets(packetChan <-chan *Packet) {
	for {
		packet := <-packetChan

		headerStr := fmt.Sprintf("%s packet sent from %s to %s\n",
			packet.server, packet.fromName, packet.toName)
		log.Println(formatPayload(packet, headerStr))

		debug(fmt.Sprintf("Sending %d bytes from %s to %s",
			packet.size, packet.fromName, packet.toName))
		if err := send(packet.destConn, packet.data, packet.size); err != nil {
			fmt.Printf("Failed to send packet: %s\n", err.Error())
			break
		}
	}
}

func formatPayload(packet *Packet, headerStr string) string {
	var logBuf bytes.Buffer
	logBuf.WriteString(headerStr)

	name := getPacketName(packet.server, packet.command)
	if name == "" {
		logBuf.WriteString(fmt.Sprintf("Unknown packet %2x\n", packet.command))
	} else {
		logBuf.WriteString(name + "\n")
	}

	pktLen := int(packet.size)
	data := packet.decryptedData
	for rem, offset := pktLen, 0; rem > 0; rem -= displayWidth {
		if rem < displayWidth {
			appendPacketLine(&logBuf, data[(pktLen-rem):pktLen], rem, offset)
		} else {
			appendPacketLine(&logBuf, data[offset:offset+displayWidth], displayWidth, offset)
		}
		offset += displayWidth
	}
	return logBuf.String()
}

func appendPacketLine(logBuf *bytes.Buffer, data []uint8, length int, offset int) {
	logBuf.WriteString(fmt.Sprintf("(%04X) ", offset))
	// Print our bytes.
	for i, j := 0, 0; i < length; i++ {
		if j == 8 {
			// Visual aid - spacing between groups of 8 bytes.
			j = 0
			logBuf.WriteString("  ")
		}
		logBuf.WriteString(fmt.Sprintf("%02x ", data[i]))
		j++
	}
	// Fill in the gap if we don't have enough bytes to fill the line.
	for i := length; i < displayWidth; i++ {
		if i == 8 {
			logBuf.WriteString("  ")
		}
		logBuf.WriteString("   ")
	}
	logBuf.WriteString("    ")
	// Display the print characters as-is, others as periods.
	for i := 0; i < length; i++ {
		c := data[i]
		if strconv.IsPrint(rune(c)) {
			logBuf.WriteString(fmt.Sprintf("%c", data[i]))
		} else {
			logBuf.WriteString(".")
		}
	}
	logBuf.WriteString("\n")
}

func send(conn net.Conn, data []byte, size uint16) error {
	for bytesSent := uint16(0); bytesSent < size; {
		n, err := conn.Write(data[bytesSent:size])
		if err != nil {
			return err
		}
		bytesSent += uint16(n)
	}
	return nil
}
