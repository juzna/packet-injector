// Default config
global.config = {
	myMAC: "11:22:33:44:55:66",
	myIP:  "10.0.0.99",
};

var sys = require('sys');
var Buffer = require('buffer').Buffer;
var Pcap = require('pcap');
var tools = require('./tools');

var pcap = Pcap.createOfflineSession("./sample/lib.cap", 'ip');

// Received an raw packet
pcap.on('packet', function(buf) {
  var buf = buf.slice(24); // Remove radio-tap header
  
  console.log("Received packet:", buf.length, sys.inspect(buf.slice(0, 100)));
  
  var x = tools.IEEE802dot11Packet.decode(buf, 0);
  console.log(sys.inspect(x, 8));

  process.exit();
});


