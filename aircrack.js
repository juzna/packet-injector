/**
* Connection to airserv-ng server
*
* Class AirCrackConnection
*  Emits these events:
*   - connect()
*   - end()
*   - raw-packet(Buffer)
*   - unknown-aircrack-command(cmd, Buffer)
*
*  Public functions:
*    - open() - opens connection
*    - writeMessage(cmd, data, callback)
*    - send(Buffer, callback)
*    - getMac(cb) - get mac address, cb is callback with one argument, which mac address
*/

var sys = require('sys');
var net = require('net');
var eve = require('events');
var Buffer = require('buffer').Buffer;
var Pcap = require('pcap');


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


function AirCrackConnection(ip, port) {
  var self = this,
    callbackQueue = [], // Queue for callbacks of written messages
    writeQueue = [];  // Queue for pending writes
  
  self.ip = ip;
  self.port = port;
  self.opened = false;
  self.conn = null;

  // Create big buffer
  var buffer = new Buffer(4096);
  var bufferStart = 0, bufferEnd = 0;
  for(var i = 0; i < 4096; i++) buffer[i] = 0
  
  // Open connection
  self.open = function open() {
    self.conn = net.createConnection(self.port, self.ip);
    
    // On connection
    this.conn.on('connect', function() {
      self.opened = true;
      self.emit('connect');
      
      // Write all messages which are in queue
      //console.log("Socket is connected, writing ", writeQueue.length, "messages from queue");
      while(writeQueue.length > 0) {
        var item = writeQueue.shift();
        writeMessage_(item[0], item[1]);
      }
    });
    
    // On end of connection
    this.conn.on('end', function() {
      self.conn.end(); // End also my part of connection
      self.opened = false;
      self.emit('end');
    });
    
    // On received data
    this.conn.on('data', receivedData);    
  };
  
  // On received data
  function receivedData(buf) {
    // Put data to big buffer
    buf.copy(buffer, bufferEnd, 0); bufferEnd += buf.length;

    while(processBuffer()); // Process all messages in buffer
    
    cleanBuffer();
  }
  
  // Process big buffer
  function processBuffer() {
    var buf = buffer.slice(bufferStart, bufferEnd); // Get actual part of bug buffer
    if(buf.length < 5) return false; // Not enough data
    var cmd = buf[0];
    var len = buf[4] + buf[3] * 0x100 + buf[2] * 0x10000 + buf[1] * 0x1000000;
    if(buf.length < len + 5) return false; // Leave it to next time (we dont have whole data part)

    var data = buf.slice(5, len + 5);
    bufferStart += len + 5; // Move start pointer to next data

    if(cmd == commands.NET_PACKET) {
      // Emit new packet event
      self.emit('raw-packet', data);
    }
    else {
      // Execute callback
      var cb = callbackQueue.shift();
      if(typeof cb == 'function') cb(cmd, len, data); // Callback is set, cal it
      else { // No callback
        if(cmd != commands.NET_RC) self.emit('unknown-aircrack-command', cmd, data);
      }
    }

    return true; // Processed
  }
    
  // Cleans big buffer
  function cleanBuffer() {
    if(bufferStart > 0) {
      if(bufferStart == bufferEnd) { // It's empty, just move pointers
        bufferStart = bufferEnd = 0;
      }
      else {
        // Move to beggining via helper buffer
        var b2 = new Buffer(bufferEnd - bufferStart);
        buffer.copy(b2, 0, bufferStart, bufferEnd); // Copy all valid data to new buffer
        b2.copy(buffer, 0, 0); // Copy back to big buffer
        bufferStart = 0;
        bufferEnd = b2.length;
      }
    }
  }
  
  // Write message to airserv connection
  function writeMessage_(buf, cb) {
    // Send the data
    self.conn.write(buf);
    callbackQueue.push(cb);
  }
  
  // Queue writing (when not yet connected)
  function queueMessage_(buf, cb) {
    writeQueue.push([buf, cb]);
  }
  
  // Send message to airserv-ng server (returns true if actually send, or false if queues)
  self.writeMessage = function writeMessage(cmd, data, callback) {
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
    
    if(self.opened) {
      writeMessage_(buf, callback);
      //console.log("Writing message");
      return true;
    }
    else {
      queueMessage_(buf, callback);
      //console.log("Queueing message");
      return false;
    }
  };
  
  // Send packet to network
  self.send = function sendPacket(buf, cb) {
    self.writeMessage(commands.NET_WRITE, buf, cb);
  };
  
  // Get MAC address
  self.getMac = function getMac(cb) {
    self.writeMessage(commands.NET_GET_MAC, undefined, function(cmd, len, data) {
      cb(Pcap.unpack.ethernet_addr(data, 0));
    });
  }
};

// Make it instance of EventEmitter
AirCrackConnection.prototype = new eve.EventEmitter;


exports.AirCrackConnection = AirCrackConnection;

