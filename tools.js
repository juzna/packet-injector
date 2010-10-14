var Pcap = require('pcap');
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
    }
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

// Pack numbers
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
    }
};
exports.pack = pack;


var Packet = exports.Packet = Class({
  init: function(type, params) {
    this.type = typeof type == 'undefined' ? null : type;
    this.lower = null;
    
    // Extend with parameters
    extend(this, params || {});
  },
  
  // Basic methods
  _setLower: function(x) { this.lower = x; },
  _setPayload: function(x) { this.payload = x; this.payloadType = x.getType(); },
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
    x._setLower(this);
  },
  
  getLength: function() {},
  
  // Write packe to buffer
  write: function(buf, offset) {
    this.encode();
    this.buffer.copy(buf, offset, 0);
    
    return this.writePayload(buf, offset + this.buffer.length);
  },
  
  // Write payload to output buffer
  writePayload: function(buf, offset) {
    console.log('Payload is', typeof this.payload, this.payload instanceof Packet);
    if(this.payload instanceof Packet) return this.payload.write(buf, offset);
    else return offset;
  },
  
  // Get length of payload
  getPayloadLength: function() {
    var p = this.payload;
    
    if(!p) return 0;
    else if(p instanceof Packet) return p.getLength();
    else if(p instanceof Buffer) return p.length;
    else if(typeof p == 'string') return p.length;
    else throw new Error("Unknown payload type");
  },
});


// ARP Packet
var ARPPacket = exports.ARPPacket = Class({
  Extends: Packet,
  
  init: function(params) {
    Packet.prototype.init.call(this, 'arp', params); // Basic init
    
    // Default values
    defaults(this, {
	    htype: 1,	// Ethernet
	    ptype: 0x0800,	// IP
      hlen: 6,
      plen: 4,
      operation: 'request',
      sender_ha: global.config.myMAC,
      sender_pa: global.config.myIP,
      target_ha: '00:00:00:00:00:00',
      target_pa: undefined
    });
  },
  
  encode: function() {
    // Get buffer for payload
    if(!this.buffer) this.buffer = new Buffer(28);
    var buf = this.buffer;
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
    
    return buf;
  },  
});

extend(ARPPacket, {
  // Decore ARP packet from buffer
  decode: function(raw_packet, offset) {
    var pkt = new ARPPacket;
    if(typeof offset == 'undefined') offset = 0;
    
    // Unpack packet
    var ret = Pcap.decode.arp(raw_packet, offset);
    return extend(pkt, ret);
  },
});



// Ethernet packet
var EthernetPacket = exports.EthernetPacket = Class({
  Extends: Packet,
  
  init: function(params, payload) {
    Packet.prototype.init.call(this, 'ethernet', params); // Basic init

    // Default values
    defaults(this, {
      ethertype: 0x0800,
      shost: global.config.myMAC,
    });
    
    // Set payload
    if(payload) this.payload = payload;
  },
  
  encode: function() {
    // Get buffer for payload
    if(!this.buffer) this.buffer = new Buffer(14);
    var buf = this.buffer;
    var offset = 0;
    
    // Find ethertype based on payload
    if(this.payload && this.payload instanceof Packet) {
      if(this.payload instanceof ARPPacket) this.ethertype = 0x0806;
//      else if(this.payload instanceof IPPacket) this.ethertype = 0x0800;
    }

    pack.ethernet_addr(this.dhost, buf, offset + 0); // Destination MAC address
    pack.ethernet_addr(this.shost, buf, offset + 6); // Source MAC address
    pack.uint16(this.ethertype, buf, offset + 12);   // Ethernet type
    
    return buf;
  },  
});

extend(EthernetPacket, {
  decode: function(raw_packet, offset) {
    var pkt = new EthernetPacket;
    if(typeof offset == 'undefined') offset = 0;
    
    // Unpack packet
    var ret = Pcap.decode.ethernet(raw_packet, offset);
    
    // Set payload
    if(ret.arp) {
      pkt.setPayload(new ARPPacket(ret.arp));
      delete ret.arp;
    }
    else if(ret.ip) {
      pkt.setPayload(new IPPacket(ret.ip));
      delete ret.ip;
    }
    
    return extend(pkt, ret);
  },
});








// IP Packet
var IPPacket = exports.IPPacket = Class({
  Extends: Packet,
  
  init: function(params, payload) {
    Packet.prototype.init.call(this, 'ip', params); // Basic init
    
    // Default values
    defaults(this, {
      version: 4,
      header_length: 5, // Length of header in 32bit words
      diffserv: 0,
      identification: Math.floor(Math.random()*0x10000), // Random 16bit integer
      ttl: 68,
      saddr: global.config.myIP,
      daddr: undefined,
    });
    
    if(payload) this.payload = payload;
  },
  
  // Get protocol number of payload (http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
  getPayloadProtocolNumber: function() {
    switch(this.getPayloadType()) {
      case 'icmp': return 1;
      case 'tcp':  return 6;
      case 'udp':  return 17;
      default: throw new Error("Unknown protocol paylaod in IP");
    }
  },
  
  encode: function() {
    // Get buffer for payload
    if(!this.buffer) this.buffer = new Buffer(20);
    var buf = this.buffer;
    var offset = 0;
    
    buf[0] = ((this.version >> 4) & 0xf0) | (this.header_length & 0x0f); // Version + header len
    buf[1] = this.diffserv; // Diffserv tag
    pack.uint16(this.getPayloadLength() + 20, buf, 2); // Total length in bytes
    pack.uint16(this.identification, buf, 4); // Packet unique ID
    pack.uint16(0, buf, 6); // Flags + frafment offset
    buf[8] = this.ttl; // Time to live
    buf[9] = this.getPayloadProtocolNumber();
    buf[10] = buf[11] = 0; // Checksum - gotta calculate it later
    pack.ipv4_addr(this.saddr, buf, 12);    
    pack.ipv4_addr(this.daddr, buf, 16);
    
    // Calculate checksum
    // TODO:

    return buf;
  },  
});

extend(IPPacket, {
  // Decore IP packet from buffer
  decode: function(raw_packet, offset) {
    var pkt = new IPPacket;
    if(typeof offset == 'undefined') offset = 0;
    
    // Unpack packet
    var ret = Pcap.decode.ip(raw_packet, offset);
    
    // TODO: decode payload
    
    return extend(pkt, ret);
  },
});


var TCPPacket = exports.TCPPacket = Class({
  Extends: Packet,

  init: function(params, payload) {
    Packet.prototype.init.call(this, 'tcp', params); // Basic init
    
    // Default values
    defaults(this, {
      // TODO: finish
    });
    
    if(payload) this.payload = payload;
  },
  
  encode: function() {
   return this.buffer = new Buffer(1);
  },
});
