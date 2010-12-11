var sys = require('sys');
var Buffer = require('buffer').Buffer;
var Pcap = require('pcap');
var tools = require('./tools');
require('./config');

// Assume first argument is source name
var sourceName = process.argv[2];
if(typeof sourceName == 'undefined') {
  console.log("You shoud give a source name");
  process.exit(1);
}

var src = global.sources[sourceName];
if(!src) throw new Error("Source not found");


// Create connection
var conn;
if(typeof src.constructor == 'function') {
  conn = src.constructor.apply(this, src.arguments || []);
}
else {
  var f = function() {};
  var cons = require(src.library)[src.constructor]; // Get original constructor
  f.prototype = cons.prototype;
  conn = new f;
  cons.apply(conn, src.arguments || []);

  // Open connection
  conn.open();
}


// On MAC address change (or when it's received for first time)
conn.on('mac', function(mac) {
  global.config.myMAC = mac;
  console.log("Mac address is: " + mac);
});

// Ond end of connection
conn.on('end', function () {
  sys.print("End of connection\n");
});

// Received an raw packet -> decode it
conn.on('packet', function(buf) {
  var pkt;
  if(src.filter && !src.filter(buf)) return; // Not passed thru filter
  if(src.byteLimit) buf = buf.slice(0, src.byteLimit);
  
  console.log("Received packet", sys.inspect(buf.length > 100 ? buf.slice(0, 100) : buf));
  
  if(typeof src.decoder == 'string') pkt = tools[src.decoder].decode(buf, 0);
  else if(typeof src.decoder == 'function') pkt = src.decoder(buf);
  if(!pkt) return;
  
  // Emit new event
  var eventName = 'packet.' + pkt.getType();
  console.log("Emiting event", eventName, sys.inspect(pkt));
  conn.emit(eventName, pkt);
  process.exit();
});


var air = conn;


// Ethernet packet
conn.on('packet.ethernet', function(eth) {
  var ptype = eth.getPayloadType();
  
  switch(ptype) {
    case 'ip':
      conn.emit('packet.ip', eth.payload);
      break;
      
    case 'arp':
      conn.emit('packet.arp', eth.payload);
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


console.log("Konec");
