var sys = require('sys');
var Buffer = require('buffer').Buffer;
var tools = require('./tools');
var Pcap = require('pcap');

// Default config
global.config = {
	myMAC: "11:22:33:44:55:66",
	myIP:  "10.0.0.99",
};

//console.log(sys.inspect(tools.ARPPacket));

// Create ARP packet
var arp = new tools.ARPPacket( { target_pa: '10.0.0.127' } );

//Create IP packet
var ip = new tools.IPPacket( { daddr: '10.0.0.5' }, new tools.TCPPacket );


var payload = ip;

// Create ethernet packet containing ARP
var ethParams = { dhost: 'ff:ff:ff:ff:ff:ff' };
var eth = new tools.EthernetPacket(ethParams, payload);


// Write to buffer
var b = new Buffer(1024);
var end = eth.write(b, 0);

console.log(end, sys.inspect(b2 = b.slice(0, end)));
console.log(tools.EthernetPacket.decode(b2));


