var udt = require('udt');
var fs = require('fs');

// check arguments
if (process.argv.length < 3) {
	console.log('Usage: node sendfile_srv.js port\n');
	process.exit(-1);
}
var port = parseInt(process.argv[2], 10);

var srv = udt.createServer(function(socket){
    var fn = './dummy/file_recv@'+Date.now()+'.txt';
    var file_stream = fs.createWriteStream(fn);
    socket.pipe(file_stream);
    console.log('write file to '+fn);
});

srv.listen(port);
console.log('UDP file server listen on '+port);
