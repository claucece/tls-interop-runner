package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
)

type ClientHello struct {
	version           uint16
	supportsDC        bool
	serverName        string
	supportedVersions []uint16
}

type ServerHello struct {
	version uint16
}

type Transcript struct {
	clientHello ClientHello
	serverHello ServerHello
}

func parsePcap(tsharkPath string, pcapPath string, keylogPath string) Transcript {
	rawJSON, err := exec.Command(tsharkPath,
		"-r", pcapPath,
		"-d", "tcp.port==4433,ssl",
		"-2R", "ssl",
		"-o", fmt.Sprintf("tls.keylog_file:%s", keylogPath),
		"-T", "ek",
		"-J", "tls",
		"-l").Output()
	if err != nil {
		panic(err)
	}

	transcript := Transcript{}

	d := json.NewDecoder(bytes.NewReader(rawJSON))
	for {
		var v map[string]interface{}
		err := d.Decode(&v)
		if err != nil {
			// io.EOF is expected at end of stream.
			if err != io.EOF {
				log.Fatal(err)
			}
			break
		}

		handshakeTypes := map[string]bool{}
		if v["layers"] != nil {
			tls := v["layers"].(map[string]interface{})["tls"].(map[string]interface{})
			switch w := tls["tls_tls_handshake_type"].(type) {
			case string:
				handshakeTypes[w] = true
			case []interface{}:
				for _, val := range w {
					handshakeTypes[val.(string)] = true
				}
			}
			if handshakeTypes["1"] {
				converted, _ := strconv.ParseUint(tls["tls_tls_handshake_version"].(string), 0, 16)
				transcript.clientHello.version = uint16(converted)
				transcript.clientHello.serverName = tls["tls_tls_handshake_extensions_server_name"].(string)
				for _, val := range tls["tls_tls_handshake_extension_type"].([]interface{}) {
					if val == "34" {
						transcript.clientHello.supportsDC = true
					}
				}
				for _, val := range tls["tls_tls_handshake_extensions_supported_version"].([]interface{}) {
					converted, _ := strconv.ParseUint(val.(string), 0, 16)
					transcript.clientHello.supportedVersions = append(transcript.clientHello.supportedVersions, uint16(converted))
				}
			} else if handshakeTypes["2"] {
				converted, _ := strconv.ParseUint(tls["tls_tls_handshake_version"].(string), 0, 16)
				transcript.serverHello.version = uint16(converted)
			}
		}
	}

	return transcript
}
