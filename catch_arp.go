package main

import (
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"fmt"
	"bytes"
	"log"
)

var (
	snapshot_len int32 = 1600
	promiscuous bool = false
	timeout time.Duration = 500 * time.Millisecond
);

func main() {
	handle, err := pcap.OpenLive("en0", snapshot_len, promiscuous, timeout);
	defer handle.Close()

	err = handle.SetBPFFilter("port 67 or port 68")
	checkErr(err)

	macBroadcast, _ := net.ParseMAC("FF:FF:FF:FF:FF:FF")

	fmt.Println("start.")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		if bytes.Equal(ethernetPacket.DstMAC, macBroadcast) {
			fmt.Println("hoge")
			//Amazon Dush Button, Push?
			fmt.Printf("%#v\n", ethernetPacket.SrcMAC.String()) //※
		}
	}
}

func checkErr(err error)  {
	if err != nil {
		log.Fatalln(err)
		panic(err)
	}
}
