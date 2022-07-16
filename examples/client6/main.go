package main

import (
	"flag"
	"log"

	"github.com/insomniacslk/dhcp/dhcpv4/client4"
)

var (
	iface = flag.String("i", "ens192", "Interface to configure via DHCPv6")
)

func main() {
	flag.Parse()
	log.Printf("Starting DHCPv6 client on interface jsjs %s", *iface)

	// NewClient sets up a new DHCPv6 client with default values
	// for read and write timeouts, for destination address and listening
	// address
	client := client4.NewClient()

	// Exchange runs a Solicit-Advertise-Request-Reply transaction on the
	// specified network interface, and returns a list of DHCPv6 packets
	// (a "conversation") and an error if any. Notice that Exchange may
	// return a non-empty packet list even if there is an error. This is
	// intended, because the transaction may fail at any point, and we
	// still want to know what packets were exchanged until then.
	// A default Solicit packet will be used during the "conversation",
	// which can be manipulated by using modifiers.
	_, err := client.Exchange(*iface)

	// log.Print("-----------------------------------------")
	// Summary() prints a verbose representation of the exchanged packets.

	// for _, packet := range conversation {
	// 	log.Print(packet.Summary())
	// }

	// error handling is done *after* printing, so we still print the
	// exchanged packets if any, as explained above.
	if err != nil {
		log.Fatal(err)
	}
}
