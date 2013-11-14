var udt = require('udt');
var fs = require('fs');

var cln = udt.connect({port:51699, host: 'localhost'}, function(){
    console.log('UDP file client connected to localhost:51666');
    var file_stream = fs.createReadStream('./dummy/file_send.txt');
    
    file_stream.pipe(cln);
    
    cln.on('end', function(){
        console.log('send file done');
    });
});

