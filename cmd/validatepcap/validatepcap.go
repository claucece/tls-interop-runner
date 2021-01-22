package main

import (
	"flag"
	"fmt"
	"log"
)

const usage = `Usage:

    $ validatepcap [-help] {-pcap-in} {-keylog-in} {-testcase}
`

func main() {
	log.SetFlags(0)
	var (
		pcapPath   = flag.String("pcap-in", "", "")
		keylogPath = flag.String("keylog-in", "", "")
		testcase   = flag.String("testcase", "", "")
		help       = flag.Bool("help", false, "")
	)
	flag.Parse()
	if *help {
		fmt.Print(usage)
		return
	}
	if *pcapPath == "" || *keylogPath == "" || *testcase == "" {
		log.Fatalln("ERROR: The command requires a PCAP path, keylog path, as well as a testcase.")
	}

	transcript := parsePcap("tshark", *pcapPath, *keylogPath)

	if !validateTranscript(transcript, *testcase) {
		log.Printf("Testcase %s failed.\n", *testcase)
	} else {
		log.Printf("Testcase %s passed!\n", *testcase)
	}
}
