package main

import (
	"time"
)

const (
	RedirectType uint16 = 0x19
)

// PacketMsg contains metadata about a received packet along with the raw
// bytes of the packet as taken off of the wire.
type PacketMsg struct {
	command       uint16
	size          uint16
	data          []byte
	decryptedData []byte

	timestamp time.Time
	server    string
	fromName  string
	sendFunc  func()
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

type PatchRedirectPacket struct {
	Size    uint16
	Type    uint16
	IPAddr  [4]uint8
	Port    uint16
	Padding uint16
}

type WelcomePkt struct {
	Header
	Flags        uint32
	Copyright    [96]byte
	ServerVector [48]byte
	ClientVector [48]byte
}

type RedirectPacket struct {
	Size    uint16
	Type    uint16
	Flags   uint32
	IPAddr  [4]uint8
	Port    uint16
	Padding uint16
}

// Packet aliases expressed in big-endian.
var packetNames = map[string]map[uint16]string{
	"LOGIN": map[uint16]string{
		0x93: "LoginType",
		0xE6: "LoginSecurityType",
	},
	"CHARACTER": map[uint16]string{
		0x93:   "LoginType",
		0xE6:   "LoginSecurityType",
		0x1A:   "LoginClientMessageType",
		0xE0:   "LoginOptionsRequestType",
		0xE2:   "LoginOptionsType",
		0xE3:   "LoginCharPreviewReqType",
		0xE4:   "LoginCharAckType",
		0xE5:   "LoginCharPreviewType",
		0x01E8: "LoginChecksumType",
		0x02E8: "LoginChecksumAckType",
		0x03E8: "LoginGuildcardReqType",
		0x01DC: "LoginGuildcardHeaderType",
		0x02DC: "LoginGuildcardChunkType",
		0x03DC: "LoginGuildcardChunkReqType",
		0x01EB: "LoginParameterHeaderType",
		0x02EB: "LoginParameterChunkType",
		0x03EB: "LoginParameterChunkReqType",
		0x04EB: "LoginParameterHeaderReqType",
		0xEC:   "LoginSetFlagType",
		0xB1:   "LoginTimestampType",
		0xA0:   "LoginShipListType",
		0xEE:   "LoginScrollMessageType",
	},
	// Packets found on multiple servers.
	"COMMON": map[uint16]string{
		0x03:         "WelcomeType",
		0x07:         "BlockListType",
		0x83:         "LobbyListType",
		0x05:         "DisconnectType",
		RedirectType: "RedirectType",
		0x10:         "MenuSelectType",
	},
}

func getPacketName(serverName string, packetType uint16) string {
	name := packetNames[serverName][packetType]
	if name != "" {
		return name
	}
	return packetNames["COMMON"][packetType]
}
