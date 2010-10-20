/**
* Pokusy
*/


// Default config
global.config = {
	myMAC: "11:22:33:44:55:66",
	myIP:  "10.0.0.99",
};

var sys = require('sys');
var Buffer = require('buffer').Buffer;
var tools = require('./tools');
var Pcap = require('pcap');


// Create UDP packet
var udp = new tools.UDPPacket( {}, "ABCDEFGH");

// Create ARP packet
var arp = new tools.ARPPacket( { target_pa: '10.0.0.127' } );

// Create IP packet
var ip = new tools.IPPacket( { daddr: '10.0.0.5' }, udp );

// Create Ethernet
var ethParams = { dhost: 'ff:ff:ff:ff:ff:ff' };
var eth = new tools.EthernetPacket(ethParams, ip);


// Write to buffer
var buf = eth.encode();

console.log("Encoded packet is:", sys.inspect(buf));
console.log("After decode: ", sys.inspect(tools.EthernetPacket.decode(buf, 0)));


