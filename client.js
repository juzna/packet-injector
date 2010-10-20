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
var air = new AC('localhost', 6666);
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



// Received an raw packet
air.on('raw-packet', function(buf) {
  console.log("Received packet:", sys.inspect(buf));
  
  // Decode as ethernet packet
  var eth = tools.EthernetPacket.decode(buf, 0);
  
  // Emit packet.ethernet event
  air.emit('packet.ethernet', eth);
});


// Ethernet packet
air.on('packet.ethernet', function(eth) {
  var ptype = eth.getPayloadType();
  
  switch(ptype) {
    case 'ip':
      air.emit('packet.ip', eth.payload);
      break;
      
    case 'arp':
      air.emit('packet.arp', eth.payload);
      break;
  }
});

// On IP packet
air.on('packet.ip', function(ip) {
  var ptype = ip.getPayloadType();
  console.log("Got IP packet with ", ptype, "payload");
  
  switch(ptype) {
    case 'icmp':
      air.emit('packet.icmp', ip.payload);
      break;
      
    case 'udp':
      air.emit('packet.udp', ip.payload);
      break;
  }
});   




// ARP request -> send something
air.on('packet.arp', function(arp) {
  if(arp.operation == 'request' && arp.target_pa == '10.0.0.7') {
    var reply = arp.reply( { sender_ha: global.config.myMAC } );
    air.sendPacket(reply);
    console.log(sys.inspect(reply));    
  }
});


// On ping request, send response
air.on('packet.icmp', function(icmp) {
  if(icmp.icmp_type == 8 && icmp.lower.daddr == '10.0.0.7') {
    var reply = icmp.reply();
    air.sendPacket(reply);
    console.log(sys.inspect(reply));
  }
});
