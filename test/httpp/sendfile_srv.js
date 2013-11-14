var udt = require('udt');
var fs = require('fs');

var srv = udt.createServer(function(socket){
    var fn = './dummy/file_recv@'+Date.now()+'.txt';
    var file_stream = fs.createWriteStream(fn);
    socket.pipe(file_stream);
    console.log('write file to '+fn);
});

srv.listen(51699);
console.log('UDP file server listen on 51699');
