package main

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
)

const displayWidth = 16

var packetChan = make(chan *PacketMsg, 500)

// Handler for any packets intercepted by the proxy. Responsible for sending the packets to
// their intended destination as well as doing any logging we care about.
func consumePackets(packetChan <-chan *PacketMsg) {
	for {
		packet := <-packetChan
		log.Println(formatPayload(packet, fmt.Sprintf(
			"%s %s packet\n", packet.server, packet.fromName)))
		packet.sendFunc()
	}
}

func formatPayload(packet *PacketMsg, headerStr string) string {
	var logBuf bytes.Buffer
	logBuf.WriteString(headerStr)

	name := getPacketName(packet.server, packet.command)
	if name == "" {
		logBuf.WriteString(fmt.Sprintf("Unknown packet %02x\n", packet.command))
	} else {
		logBuf.WriteString(name + "\n")
	}

	if *namesOnly {
		return logBuf.String()
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
