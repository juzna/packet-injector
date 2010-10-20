/**
* Unit tests for tools library
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


// Compare two packets, if they're same
function packetTest(buf1, buf2) {
  if(buf1 instanceof tools.Packet) buf1 = buf1.encode(); // Convert to buffer
  if(typeof buf2 == 'string') buf2 = tools.hexBuffer(buf2); // Convert to buffer  
  
  return tools.buffCompare(buf1, buf2);
}


// Test and log
function packetAssert(name, buf1, buf2) {
  var ret, txt;
  try {
    ret = packetTest(buf1, buf2);
  }
  catch(e) {
    txt = e.message;
  }
  if(txt === undefined) {
    txt = ret ? "OK" : "No match!!!!!!!";
  }
  
  console.log('Test ' + name + ' is ' + txt);
  return ret === true;
}
    

// Test UDP packet
var udp = new tools.UDPPacket( {}, "ABCDEFGH");
var udpHex = '66 66 66 66 00 10 00 00 41 42 43 44 45 46 47 48';
packetAssert("UDP", udp, udpHex);

// Test ARP packet
var arp = new tools.ARPPacket( { target_pa: '10.0.0.127' } );
var arpHex = '00 01 08 00 06 04 00 01 11 22 33 44 55 66 0a 00 00 63 00 00 00 00 00 00 0a 00 00 7f';
packetAssert("ARP", arp, arpHex);

// Test IP packet
var ip = new tools.IPPacket( { daddr: '10.0.0.5' }, udp );
var ipHex = '45 00 00 24 03 77 00 00 44 11 4a 61 0a 00 00 63 0a 00 00 05 66 66 66 66 00 10 36 98 41 42 43 44 45 46 47 48';
packetAssert("IP + UDP", ip, ipHex);


// Test Ethernet
var ethParams = { dhost: 'ff:ff:ff:ff:ff:ff' };
var eth = new tools.EthernetPacket(ethParams, ip);
var ethHex = 'ff ff ff ff ff ff 11 22 33 44 55 66 08 00 45 00 00 24 c8 93 00 00 44 11 85 44 0a 00 00 63 0a 00 00 05 66 66 66 66 00 10 36 98 41 42 43 44 45 46 47 48';
packetAssert("ETH + IP + UDP", eth, ethHex);


