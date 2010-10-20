/**
* Some useful JS code:
* - Class - working with classes
* - extend, defauls - extending objects
* - pack - pack structures to binary form
* - Packet - basic packet class
* - Packet.define - easy packet class creator
*
* And also packet definitions.
*  Decoders are based on code from http://github.com/mranney/node_pcap/ with some modifications
*/

var Pcap = require('pcap'), unpack = exports.unpack = Pcap.unpack;
var Buffer = require('buffer').Buffer;
var sys = require('sys');

// Working with classes
var Class = exports.Class = function Class(def) {
    // pokud není konstruktor definován, použijeme nový (nechceme použít zděděný)
    var constructor = def.hasOwnProperty('init') ? def.init : function() { };
    
    // proces vytváření třídy rozdělíme do kroků
    for (var name in Class.Initializers) {
        Class.Initializers[name].call(constructor, def[name], def);
    }
    return constructor;
};
Class.Initializers = {
    Extends: function(parent) {
        if (parent) {
            var F = function() { };
            this._superClass = F.prototype = parent.prototype;
            this.prototype = new F;
        }
    },

    Mixins: function(mixins, def) {
        // kostruktoru přidáme metodu mixin
        this.mixin = function(mixin) {
            for (var key in mixin) {
                if (key in Class.Initializers) continue;
                this.prototype[key] = mixin[key];
            }
            this.prototype.constructor = this;
        };
        // a přidanou metodu hned využijeme pro rozšíření prototype
        var objects = [def].concat(mixins || []);
        for (var i = 0, l = objects.length; i < l; i++) {
            this.mixin(objects[i]);
        }
    },
    
    // Add static functions
    Static: function(methods) {
      for(var name in methods) this[name] = methods[name];
    },
};


// Global configuration
if(!global.config) global.config = {};
var config = global.config;


// Extend
var extend = exports.extend = function(dst, src) {
  if(typeof src != 'object') return dst;

  for(var i in src) dst[i] = src[i];
  return dst;
};


// Add default values
var defaults = exports.defaults = function(dst, def) {
  for(var i in def) {
    if(!dst.hasOwnProperty(i)) dst[i] = def[i];
  }
  return dst;
}

// Convert hex-dumped buffer to byte-array
var hexBuffer = exports.hexBuffer = function(s) {
  var list = s.split(' ');
  var buf = new Buffer(list.length);
  
  for(var i = 0; i < buf.length; i++) buf[i] = parseInt(list[i], 16);
  
  return buf;
}

// Compare two buffers
var buffCompare = exports.buffCompare = function(buf1, buf2) {
  if(!(buf1 instanceof Buffer)) return false;
  if(!(buf2 instanceof Buffer)) return false;
  if(buf1.length != buf2.length) return false;
  
  for(var i = 0; i < buf1.length; i++) if(buf1[i] != buf2[i]) return false;
  
  return true;
}


// Pack numbers or other data stuctures to binary format
var pack = {
  ethernet_addr: function (mac, buf, offset) {
    var parts = mac.split(':');
    if(parts.length != 6) return false;

	  for(var i = 0; i < 6; i++) buf[offset + i] = parseInt(parts[i], 16);
	  return true;
  },
  
  uint16: function (num, buf, offset) {
	  buf[offset] = (num >> 8) & 0xff;
	  buf[offset + 1] = num & 0xff;
    return true;
  },

  uint32: function (num, buf, offset) {
	  buf[offset] = (num >> 24) & 0xff;
	  buf[offset + 1] = (num >> 16) & 0xff;
	  buf[offset + 2] = (num >> 8) & 0xff;
	  buf[offset + 3] = (num) & 0xff;
  },

  uint64: function (num, buf, offset) {
	  buf[offset] = (num >> 56) & 0xff;
	  buf[offset + 1] = (num >> 48) & 0xff;
	  buf[offset + 2] = (num >> 40) & 0xff;
	  buf[offset + 3] = (num >> 32) & 0xff;
	  buf[offset + 4] = (num >> 24) & 0xff;
	  buf[offset + 5] = (num >> 16) & 0xff;
	  buf[offset + 6] = (num >> 8) & 0xff;
	  buf[offset + 7] = (num) & 0xff;
  },

  ipv4_addr: function (ip, buf, offset) {
    var parts = ip.split('.');
  	if(parts.length != 4) return false;

	  for(var i = 0; i < 4; i++) buf[offset + i] = parseInt(parts[i]);
	  return true;
  },
};
exports.pack = pack;


/**
* Basic packet class
*/
var Packet = exports.Packet = Class({
  /**
  * Initialize packet
  * @param object params Parameters for this packet (i.e. for IP packet it could be source and dst address...)
  * @param object def Default values for parameters
  */
  init: function(params, def, payload) {
    this.lower = null;
    
    // Extend with parameters
    extend(this, params || {});
    
    // Add default parameters
    if(typeof def == 'object') defaults(this, def);
    
    if(payload) this.setPayload(payload);
  },
  
  // Basic methods
  _setLower: function(x) { this.lower = x; },
  _setPayload: function(x) {
    this.payload = x;
    this.payloadType = (x instanceof Packet) ? x.getType() : 'raw';
  },
  getType: function() { return this.type; },
  
  // Try to find payload type
  getPayloadType: function() {
    var p = this.payload;
    if(p instanceof Packet) return p.getType();
    else return this.payloadType;
  },
  
  // Set lower
  setLower: function(_x) {
    this._setLower(_x);
    _x._setPayload(this);
  },
  
  // Set payload of this packet
  setPayload: function(x) {
    this._setPayload(x);
    if(x instanceof Packet) x._setLower(this);
  },
  
  getHeaderLength: function() {
    return this.headerLength; // As default, each class has parameter headerLength
  },
  
  getTotalLength: function() {
    // console.log("Total len of ", this.getType(), 'is ', this.getHeaderLength(), '+', this.getPayloadLength());
    return this.getHeaderLength() + this.getPayloadLength();
  },
  
  // Get length of payload
  getPayloadLength: function() {
    var p = this.payload;
    
    if(!p) return 0;
    else if(p instanceof Packet) return p.getTotalLength();
    else if(p instanceof Buffer) return p.length;
    else if(typeof p == 'string') return p.length;
    else throw new Error("Unknown payload type");
  },
  
  // Encode packet to byte array
  encode: function(buf) {
    //console.log(this.type, sys.inspect(this), sys.inspect(buf));
    // Create new buffer, if needed
    if(buf === undefined) {
      buf = new Buffer(this.getTotalLength());
      for(var i = 0; i < buf.length; i++) buf[i] = 0;
    }
    
    // Write actual header
    var offset = this._encodeHeader(buf);
    if(offset === undefined) offset = this.getHeaderLength();

    // Encode payload 
    //console.log("Encoding payload:", this.getPayloadType(), offset, this.getPayloadLength());
    this.encodePayload(buf, offset, this.getPayloadLength());

    // Write footer or checksums
    this._encodeFooter(buf);
    this._encodeChecksum(buf);

    return buf;
  },
  
  /**
  * Encode header and return offset, where payload should start
  */
  _encodeHeader: function(buf) {
    return this.getHeaderLength();
  },
  
  _encodeFooter: function(buf) {}, // To be overriden
  _encodeChecksum: function(buf) {}, // To be overriden

  /**
  * Encode payload of this packet to prepared buffer
  */
  encodePayload: function(buf, offset, len) {
    //console.log(this.type, offset, len);
    var p = this.payload;
    
    if(!p);
    else if(p instanceof Packet) p.encode(buf.slice(offset, offset + len));
    else if(p instanceof Buffer) p.copy(buf, offset, 0, len)
    else if(typeof p == 'string') buf.write(p, offset);
    else throw new Error("Unknown payload type");
  },
  
  /**
  * Create reply for this packet (and all lower layers)
  */
  reply: function(params, payload) {
    arguments[0] = params || {};
    console.log("Creating reply for ", this.getType(), this.lower);
    if(typeof this._reply != 'function') throw new Error("This level (" + this.getType() + ") doesnt support reply");

    // Create reply packet
    var ret = this._reply.apply(this, arguments);
    
    // Create reply for lower level
    if(this.lower) {
      if(!(this.lower instanceof Packet)) throw new Error("Lower layer is not a Packet");
      
      this.lower.reply(params.lower, ret);
    }
    
    return ret;
  },
  
  getLowest: function() {
    return this.lower ? this.lower.getLowest() : this;
  },
  
  encodeAll: function() {
    return this.getLowest().encode();
  },
});


// Creator for Packet subclasses (makes it easier ;)
Packet.define = function(exportName, options) {
  if(arguments.length == 1) {
    exportName = undefined;
    options = arguments[0];
  }

  var params = {};
  if(options.methods) extend(params, options.methods);
  params.Extends = options.baseClass || Packet;
  params.headerLength = options.headerLength;
  params.type = options.type;
  params.Static = {};
  params.Static.defaults = options.defaults || {};
  
  // Constructor wrapper
  params.init = function(par, payload) {
    params.Extends.prototype.init.call(this, par, params.Static.defaults, payload); // Basic init
    if(typeof options.init == 'function') options.init.apply(this, arguments);
  },
  
  // Decoding and encoding methods
  params.Static.decode = options.decode || function() { throw new Error("This packet doesnt support decoding"); };
  if(typeof options.encodeHeader == 'function') params._encodeHeader = options.encodeHeader;
  if(typeof options.encodeFooter == 'function') params._encodeFooter = options.encodeFooter;
  if(typeof options.encodeChecksum == 'function') params._encodeChecksum = options.encodeChecksum;
  if(typeof options.reply == 'function') params._reply = options.reply;
  
  if(options.static) extend(params.Static, options.static);
  
  // Create new class
  var cls = Class(params);
  
  // Export it
  if(exportName) exports[exportName] = cls;
  
  return cls;
}




// ARP Packet definitionn
var ARPPacket = Packet.define('ARPPacket', {
  type: 'arp',
  
  // Length of header (actually, it has no payload, so it's length of whole packet ;)
  headerLength: 28,
    
  // Default parameters
  defaults: {
    htype: 1,	// Ethernet
    ptype: 0x0800,	// IP
    hlen: 6,
    plen: 4,
    operation: 'request',
    sender_ha: global.config.myMAC,
    sender_pa: global.config.myIP,
    target_ha: '00:00:00:00:00:00',
    target_pa: undefined
  },
    
  // Decore ARP packet from buffer
  decode: function(buf, offset) {
    if(typeof offset == 'undefined') offset = 0;
    
    // Unpack packet
    var details = Pcap.decode.arp(buf, offset);
    return new ARPPacket(details);
  },
  
  // Encoder
  encodeHeader: function(buf) {
    var offset = 0;
    
    // Validate data
    if(!this.target_pa) throw new Error("Target IP not defined");
    if(this.operation == 'request') this.operationCode = 1;
    else if(this.operation == 'reply') this.operationCode = 2;
    else throw new Error("Unknown type of ARP packet");

    // Create packet
    pack.uint16(this.htype, buf, offset + 0);
    pack.uint16(this.ptype, buf, offset + 2);
    buf[offset + 4] = this.hlen;
    buf[offset + 5] = this.plen;
    pack.uint16(this.operationCode, buf, offset + 6);

    // Write addresses
    pack.ethernet_addr(this.sender_ha, buf, offset + 8);
    pack.ipv4_addr(this.sender_pa, buf, offset + 14);
    pack.ethernet_addr(this.target_ha, buf, offset + 18);
    pack.ipv4_addr(this.target_pa, buf, offset + 24);
  },
  
  reply: function(params) {
    if(this.operation != 'request') throw new Error("Unable to reply, this is not a request");
    
    // Update parameters for lower level (ethernet layer)
    if(!params.lower) params.lower = {};
    if(!params.lower.shost && params.sender_ha) params.lower.shost = params.sender_ha;
    
    
    return new ARPPacket(extend({
      operation: 'reply',
      target_ha: this.sender_ha,
      target_pa: this.sender_pa,
      sender_pa: this.target_pa, // Requested IP
    }, params));
  },
});



// Ethernet packet definition
var EthernetPacket = Packet.define('EthernetPacket', {
  type: 'ethernet',
  
  headerLength: 14,

  defaults: {
    ethertype: 0x0800,
    shost: global.config.myMAC,
  },
    
  decode: function(raw_packet, offset) {
    var payload, ret = {};
    
    ret.dhost = unpack.ethernet_addr(raw_packet, 0);
    ret.shost = unpack.ethernet_addr(raw_packet, 6);
    ret.ethertype = unpack.uint16(raw_packet, 12);

    switch (ret.ethertype) {
      case 0x800: // IPv4
        payload = IPPacket.decode(raw_packet, offset + 14);
        break;
      
      case 0x806: // ARP
        payload = ARPPacket.decode(raw_packet, offset + 14);
        break;
    }
    
    return new EthernetPacket(ret, payload);
  },
 
  encodeHeader: function(buf) {
    var offset = 0;
    
    // Find ethertype based on payload
    if(this.payload && this.payload instanceof Packet) {
      if(this.payload instanceof ARPPacket) this.ethertype = 0x0806;
      else if(this.payload instanceof IPPacket) this.ethertype = 0x0800;
    }

    pack.ethernet_addr(this.dhost, buf, offset + 0); // Destination MAC address
    pack.ethernet_addr(this.shost, buf, offset + 6); // Source MAC address
    pack.uint16(this.ethertype, buf, offset + 12);   // Ethernet type
  },
  
  // Create reply for this packet
  reply: function(params, payload) {
    return new EthernetPacket(extend({
      dhost: this.shost,
      shost: this.dhost,
      ethertype: this.ethertype,
    }, params || {}), payload);
  },
});





// IP Packet definition
var IPPacket = Packet.define('IPPacket', {
  type: 'ip',
  
  headerLength: 20,
  
  // Default values
  defaults: {
    version: 4,
    header_bytes: 20,
    diffserv: 0,
    identification: Math.floor(Math.random()*0x10000), // Random 16bit integer
    ttl: 68,
    saddr: global.config.myIP,
    daddr: undefined,
  },
  
  // Decore IP packet from buffer
  decode: function(buf, offset) {
    //console.log("Decoding IP packet", offset, buf.length - offset, sys.inspect(buf.slice(offset)));
    var ret = {}, payload;
    
    // http://en.wikipedia.org/wiki/IPv4
    ret.version = (buf[offset] & 240) >> 4; // first 4 bits
    ret.header_length = buf[offset] & 15; // second 4 bits
    ret.header_bytes = ret.header_length * 4;
    ret.diffserv = buf[offset + 1];
    ret.total_length = unpack.uint16(buf, offset + 2); // 2, 3
    ret.identification = unpack.uint16(buf, offset + 4); // 4, 5
    ret.flags = {};
    ret.flags.reserved = (buf[offset + 6] & 128) >> 7;
    ret.flags.df = (buf[offset + 6] & 64) >> 6;
    ret.flags.mf = (buf[offset + 6] & 32) >> 5;
    ret.fragment_offset = ((buf[offset + 6] & 31) * 256) + buf[offset + 7]; // 13-bits from 6, 7
    ret.ttl = buf[offset + 8];
    ret.protocol = buf[offset + 9];
    ret.header_checksum = unpack.uint16(buf, offset + 10); // 10, 11
    ret.saddr = unpack.ipv4_addr(buf, offset + 12); // 12, 13, 14, 15
    ret.daddr = unpack.ipv4_addr(buf, offset + 16); // 16, 17, 18, 19    
    
    // Decode payload
    var pData = offset + (ret.header_length * 4); // Pointer to data position
    try {
      switch(ret.protocol) {
        case 1:
          ret.protocol_name = "ICMP";
          payload = ICMPPacket.decode(buf, pData);
          break;
          
        case 2:
          ret.protocol_name = "IGMP";
          //ret.igmp = decode.igmp(raw_packet, offset + (ret.header_length * 4));
          break;
          
        case 6:
          ret.protocol_name = "TCP";
          //ret.tcp = decode.tcp(raw_packet, offset + (ret.header_length * 4), ret);
          break;
          
        case 17:
          ret.protocol_name = "UDP";
          payload = UDPPacket.decode(buf, pData);
          break;
          
        default:
          ret.protocol_name = "Unknown";
          payload = buf.slice(pData);
      }
    }
    catch(e) {
      ret.payload_error = e;
      ret.payload = buf.slice(pData);
    }
    
    return new IPPacket(ret, payload);
  },
  
  encodeHeader: function(buf) {
    this.header_length = this.header_bytes / 4;
    buf[0] = ((this.version << 4) & 0xf0) | (this.header_length & 0x0f); // Version + header len
    buf[1] = this.diffserv; // Diffserv tag
    pack.uint16(this.getTotalLength(), buf, 2); // Total length in bytes
    pack.uint16(this.identification, buf, 4); // Packet unique ID
    pack.uint16(0, buf, 6); // Flags + frafment offset
    buf[8] = this.ttl; // Time to live
    buf[9] = this.getPayloadProtocolNumber();
    buf[10] = buf[11] = 0; // Checksum - gotta calculate it later
    pack.ipv4_addr(this.saddr, buf, 12);    
    pack.ipv4_addr(this.daddr, buf, 16);
  },
  
  encodeChecksum: function(buf) {
    var checksum = this.checksum(buf, 0, buf.length);
    pack.uint16(checksum, buf, 10);
  },
  
  reply: function(params, payload) {
    return new IPPacket(extend({
      saddr: this.daddr,
      daddr: this.saddr,
      identification: this.identification,
    }, params), payload);
  },
  
  // Another methods
  methods: {
    // Get protocol number of payload (http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
    getPayloadProtocolNumber: function() {
      switch(this.getPayloadType()) {
        case 'icmp': return 1;
        case 'tcp':  return 6;
        case 'udp':  return 17;
        default: throw new Error("Unknown protocol paylaod in IP");
      }
    },

    /**
    * Calculates IP checksum value. Can be used also for other protocols, like UDP or TCP
    * @param Buffer buf Byte array buffer of data to be checksumed
    * @param int offset Starting position in buffer
    * @param int len Length of data for checksum computation
    * @param int sum Optional, can be used for pseudo-headers (e.g. for UDP)
    */
    checksum: function(buf, offset, len, sum) {
      if(typeof sum != 'number') sum = 0;
      
      // Sum all 16bit words
      for(var i = 0; i < len; i += 2) {
        sum += (buf[offset + i] << 8) + buf[offset + i + 1];
      }

      // Add carry bits to create 16bit integer
      while(sum >> 16) sum = (sum & 0xffff) + (sum >> 16)
      
      // Return complement
      return ~sum;
    },

    payloadChecksum: function(buf, offset, len, protocol) {
      // Pseudo header
      var buf2 = new Buffer(12);
      pack.ipv4_addr(this.saddr, buf2, 0);    
      pack.ipv4_addr(this.daddr, buf2, 4);  
      buf2[8] = 0; // Zeros
      buf2[9] = protocol;
      pack.uint16(len, buf2, 10); // Length of header + payload
      var sum = IPPacket.prototype.checksum(buf2, 0, 12, 0); // Start computing checksum

      // Compute checksum of rest of packet
      return IPPacket.prototype.checksum(buf, offset, len, sum);
    },
  },
});


// UDP packet definition
var UDPPacket = Packet.define('UDPPacket', {
  type: 'udp',
  headerLength: 8,
  defaults: {
    sport: 0x6666,
    dport: 0x6666,
  },
  
  decode: function(buf, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/User_Datagram_Protocol
    ret.sport = unpack.uint16(buf, offset); // 0, 1
    ret.dport = unpack.uint16(buf, offset + 2); // 2, 3
    ret.length = unpack.uint16(buf, offset + 4); // 4, 5
    ret.checksum = unpack.uint16(buf, offset + 6); // 6, 7
    
    return new UDPPacket(ret, buf.slice(offset + 8));
  },
  
  encodeHeader: function(buf) {
    pack.uint16(this.sport, buf, 0); // Source port
    pack.uint16(this.dport, buf, 2); // Destination port
    pack.uint16(this.getTotalLength(), buf, 4); // length
    buf[6] = buf[7] = 0; // Checksum - gotta calculate it later
  },
  
  encodeChecksum: function(buf) {
    if(!this.lower) return; // No calculation of checksum
    
    if(!(this.lower instanceof IPPacket)) throw new Error("This packet doesnt have IP packet, which is needed for checksum computation");
    var checksum = this.lower.payloadChecksum(buf, 0, this.getTotalLength(), 17);
    pack.uint16(checksum, buf, 6); 
  },
  
  reply: function(params, payload) {
    return new UDPPacket(extend({
      sport: this.dport,
      dport: this.sport,
    }, params), payload);
  },
});



// ICMP packet definition
var ICMPPacket = Packet.define('ICMPPacket', {
  type: 'icmp',
  headerLength: 8,
  defaults: {
    icmp_type: 8, // Ping request
    code: 0,
    id: Math.floor(Math.random()*0x10000), // Random 16bit integer
    sequence: Math.floor(Math.random()*0x10000), // Random 16bit integer
  },
  
  decode: function(buf, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    ret.icmp_type = buf[offset];
    ret.code = buf[offset + 1];
    ret.checksum = unpack.uint16(buf, offset + 2); // 2, 3
    ret.id = unpack.uint16(buf, offset + 4); // 4, 5
    ret.sequence = unpack.uint16(buf, offset + 6); // 6, 7
    
    return new ICMPPacket(ret, buf.slice(offset + 8));
  },
  
  encodeHeader: function(buf) {
    buf[0] = this.icmp_type;
    buf[1] = this.code;
    buf[2] = buf[3] = 0; // Checksum, to be added later
    pack.uint16(this.id, buf, 4);
    pack.uint16(this.sequence, buf, 6);
  },
  
  encodeChecksum: function(buf) {
    var checksum = IPPacket.prototype.checksum(buf, 0, this.getTotalLength());
    pack.uint16(checksum, buf, 2);
  },
  
  reply: function(params, payload) {
    if(this.icmp_type == 8) {
      return new ICMPPacket(extend({
        icmp_type: 0,
        code: 0,
        id: this.id,
        sequence: this.sequence
      }, params), payload || this.payload);
    }
    
    else throw new Error("Dont know how to create a reply");
  }
});
