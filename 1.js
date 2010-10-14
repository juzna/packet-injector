var net = require('net');
var server = net.createServer(function (stream) {
  // stream.setEncoding('utf8');
  stream.on('connect', function () {
    stream.write('hello\r\n');
  });
  stream.on('data', function (data) {
    stream.write(data);
  });
  stream.on('end', function () {
    stream.write('goodbye\r\n');
    stream.end();
  });
});
server.listen(8124, 'localhost');
