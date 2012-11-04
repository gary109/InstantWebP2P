var http = require('http');
var srv = http.createServer(function(req, res){
  res.end('Hi, just say hi to you over TCP ...\n');
});
srv.listen(51688);
console.log('HTTPP server listing on TCP port 51688');
