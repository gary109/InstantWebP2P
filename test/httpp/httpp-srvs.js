var httpp = require('httpp');
var srv = httpp.createServer(function(req, res){
  res.end('Hi, just say hi to you over UDP ...\n');
});
srv.listen(51688);
console.log('HTTPP server listing on UDP port 51688');

var srv1 = httpp.createServer(function(req, res){
  res.end('Hi, just say hi to you over UDP ...\n');
});
srv1.listen(51886);
console.log('HTTPP server listing on UDP port 51886');

