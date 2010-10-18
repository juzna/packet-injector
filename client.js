var sys = require('sys');
var net = require('net');
var conn = net.createConnection(6666, 'localhost');
var Buffer = require('buffer').Buffer;
var chr = String.fromCharCode;
var Pcap = require('pcap');
var pcap = new Pcap.Pcap;
var tools = require('./tools');

// Default config
var config = {
	myMAC: "11:22:33:44:55:66",
	myIP:  "10.0.0.99",
};



// Aircrack commands
var commands = {
	NET_RC:		1,
	NET_GET_CHAN:	2,
	NET_SET_CHAN:	3,
	NET_WRITE:	4,
	NET_PACKET:	5,
	NET_GET_MAC:	6,
	NET_MAC:	7,
	NET_GET_MONITOR:8,
	NET_GET_RATE:	9,
	NET_SET_RATE:	10,
};

var callbackQueue = [];

// Write message to airserv
function writeMessage(cmd, data, callback) {
  var len = data ? data.length : 0;
  var buf = new Buffer(5 + len);

  // Command
  buf[0] = cmd;

  // Length
  buf[4] = len & 0xff;
  buf[3] = (len >> 8) & 0xff;
  buf[2] = (len >> 16) & 0xff;
  buf[1] = (len >> 24) & 0xff;

  // Data
  if(data instanceof Buffer) data.copy(buf, 5, 0, len);
  else if(typeof data == 'string') buf.write(data, 5, 'ascii');
  
  // Send the data
  conn.write(buf);
  callbackQueue.push(callback);
}

// On connect
conn.on('connect', function() {
  writeMessage(commands.NET_GET_MAC, undefined, function(cmd, len, data) {
    config.myMAC = Pcap.unpack.ethernet_addr(data, 0);
    console.log("Mac address is: ", sys.inspect(config.myMAC));
  });
});

// Big buffer for data
var bb = new Buffer(4096);
var bbStart = 0, bbEnd = 0;
for(var i = 0; i < 4096; i++) bb[i] = 0;

// On received data
conn.on('data', function(buf) {
  buf.copy(bb, bbEnd, 0); bbEnd += buf.length;

  // Process buffer
  while(processBuffer());

  // Trim buffer
  if(bbStart > 0) {
    if(bbStart == bbEnd) { bbStart = bbEnd = 0; /*sys.debug("Buffer emptied");*/ }
    else {
      var b2 = new Buffer(bbEnd - bbStart);
      bb.copy(b2, 0, bbStart, bbEnd); // Copy to new buffer
      b2.copy(bb, 0, 0);
      bbStart = 0; bbEnd = b2.length;
//      sys.debug("Buffer trimmed");
    }
  }
});


function processBuffer() {
  var buf = bb.slice(bbStart, bbEnd); // Get actual part of bug buffer
  if(buf.length < 5) return false; 
  var cmd = buf[0];
  var len = buf[4] + buf[3] * 0x100 + buf[2] * 0x10000 + buf[1] * 0x1000000;
  if(buf.length < len + 5) return false; // Leave it to next time

  var data = buf.slice(5, len + 5);
  bbStart += len + 5;

  // Execute callback
  if(cmd == commands.NET_PACKET) {
    conn.emit('packet', data);
  }
  else if(cmd == commands.NET_RC) {
    // TODO: Check RC value?
  }
  else {
    var cb = callbackQueue.shift();
    if(typeof cb == 'function') cb(cmd, len, data);
    else conn.emit('unknown-command', cmd, data);
  }

  return true; // Processed
};

conn.on('end', function () {
  sys.print("End of connection\n");
  conn.end();
});

// Unknown Aircrack command
conn.on('unknown-command', function(cmd, buf) {
  console.log("Unknown aircrack command", cmd, sys.inspect(buf));
});


// Received an raw packet
conn.on('packet', function(buf) {
 //console.log('Packet: ', sys.inspect(buf));
 
 // Set PCAP header
 buf.pcap_header = {
  link_type: 'LINKTYPE_ETHERNET',
 };

 // Decode packet
 var details = Pcap.decode.packet(buf);
 //console.log(sys.inspect(details));

 // Emit event
 if(details.link_type == 'LINKTYPE_ETHERNET') conn.emit('packet.ethernet', buf, details, details.link);
});


// Ethernet packet
conn.on('packet.ethernet', function(buf, details, eth) {
 if(eth.arp) conn.emit('packet.arp', buf, details, eth.arp);
 else if(eth.ip) conn.emit('packet.ip', buf, details, eth.ip);
});


// ARP request -> send something
conn.on('packet.arp', function(buf, details, arp) {
 if(arp.operation == 'request') {
   var buf = new Buffer(6 + 6 + 2);
   tools.pack.ethernet_addr("ff:ff:ff:ff:ff:ff", buf, 0);
   tools.pack.ethernet_addr("01:02:03:04:05:66", buf, 6);
   tools.pack.uint16(0x8000, buf, 12);

   writeMessage(commands.NET_WRITE, buf);
 }


});

