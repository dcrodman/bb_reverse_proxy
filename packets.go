package main

import (
	"net"
	"time"
)

const (
	PatchRedirectType uint16 = 0x14
	RedirectType      uint16 = 0x19
)

type Packet struct {
	command       uint16
	size          uint16
	data          []byte
	decryptedData []byte

	timestamp time.Time
	server    string
	fromName  string
	toName    string
	destConn  net.Conn
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

var packetNames = map[string]map[uint16]string{
	"PATCH": map[uint16]string{
		0x02:              "PatchWelcomeType",
		0x04:              "PatchLoginType",
		0x13:              "PatchMessageType",
		PatchRedirectType: "PatchRedirectType",
		0x0B:              "PatchDataAckType",
		0x0A:              "PatchDirAboveType",
		0x09:              "PatchChangeDirType",
		0x0C:              "PatchCheckFileType",
		0x0D:              "PatchFileListDoneType",
		0x0F:              "PatchFileStatusType",
		0x10:              "PatchClientListDoneType",
		0x11:              "PatchUpdateFilesType",
		0x06:              "PatchFileHeaderType",
		0x07:              "PatchFileChunkType",
		0x08:              "PatchFileCompleteType",
		0x12:              "PatchUpdateCompleteType",
	},
	"LOGIN": map[uint16]string{
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
