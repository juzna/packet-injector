// Default config
global.config = {
	myMAC: "11:22:33:44:55:66",
	myIP:  "10.0.0.99",
};

var sys = require('sys');
var Buffer = require('buffer').Buffer;
var Pcap = require('pcap');
var tools = require('./tools');
var AC = require('./aircrack').AirCrackConnection;


// Connect to AirServ
var air = new AC('localhost', 666);
air.open();

// Find my MAC address
air.getMac(function(mac) {
  global.config.myMAC = mac;
  console.log("Mac address is: " + mac);
});

// Ond end of connection
air.on('end', function () {
  sys.print("End of connection\n");
});

// Unknown Aircrack command
air.on('unknown-aircrack-command', function(cmd, buf) {
  console.log("Unknown aircrack command", cmd, sys.inspect(buf));
});

// Add wrapper for sending packets
air.sendPacket = function(pkt, cb) {
  // Encode packet and all lower layers
  var buf = pkt.encodeAll();
  
  // Send to aircrack 
  console.log('Injecting packet:', sys.inspect(buf));
  air.send(buf, cb || function() { console.log('Packet injected...'); } );
};


function dumpPacket(pkt) {
  sys.print("Packet type: " + pkt.getType() + "\n");
  if(pkt.payload) dumpPacket(pkt.payload);
}


// Received an raw packet
air.on('raw-packet', function(buf) {
  console.log("Received packet:", sys.inspect(buf));
  console.log("Received packet:", sys.inspect(buf.slice(32)));
  
  var x = tools.AirCrackRxHeader.decode(buf, 0);
  var x2 = tools.IEEE802dot11Packet.decode(buf, 32);
  
  dumpPacket(x);
  console.log('-----');
  dumpPacket(x2);
  console.log('-----');
    
  console.log(sys.inspect(x, true, 8));
  
  exit();  
  
  // Decode as ethernet packet
//  var eth = tools.EthernetPacket.decode(buf, 0);
  
  // Emit packet.ethernet event
//  air.emit('packet.ethernet', eth);
});

