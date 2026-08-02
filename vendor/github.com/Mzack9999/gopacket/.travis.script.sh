#!/bin/bash

set -ev

go test github.com/Mzack9999/gopacket
go test github.com/Mzack9999/gopacket/layers
go test github.com/Mzack9999/gopacket/tcpassembly
go test github.com/Mzack9999/gopacket/reassembly
go test github.com/Mzack9999/gopacket/pcapgo
go test github.com/Mzack9999/gopacket/pcap
sudo $(which go) test github.com/Mzack9999/gopacket/routing
