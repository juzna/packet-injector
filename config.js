// Global config
global.config = {
	myMAC: "11:22:33:44:55:66",
	myIP:  "10.0.0.99",
};

// Source list
global.sources = {
  // Aircrack protocol from ethetnet port
  'aircrack-eth': {
    description: "AirServ from ethernet port",
    library: './aircrack',
    constructor: 'AirCrackConnection',
    arguments: [ 'localhost', '6666' ],
    decoder: 'EthernetPacket',
  },
  
  // Aircrack from wifi network
  'aircrack-wifi': {
    description: "AirServ from WiFi network",
    library: './aircrack',
    constructor: 'AirCrackConnection',
    arguments: [ 'localhost', '666' ],
    decoder: 'AirCrackRxHeader',
  },
  
  // Pcap file
  'pcap-file': {
    description: "capture file",
    library: './pcap-connection',
    constructor: function() {
      return require('pcap').createOfflineSession("./sample/lib.cap", 'ip');
    },
    decoder: 'RadioTapPacket',
  },
};

