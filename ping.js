/**
* PING packet
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

// Create packet with ping payload
var pingHex = '00 0c 29 06 04 1f 00 0c 29 c1 ce c8 08 00 45 00 00 54 00 00 40 00 40 01 26 a1 0a 00 00 02 0a 00 00 07 08 00 ac 73 65 12 00 01 ae 79 bf 4c 00 00 00 00 b3 df 06 00 00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37';
var buf = tools.hexBuffer(pingHex);

// Decode as ethernet packet
var eth = tools.EthernetPacket.decode(buf, 0);
var icmp = eth.payload.payload;


console.log(sys.inspect(icmp));
console.log('--------');
console.log(sys.inspect(icmp.reply()));

