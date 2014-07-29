var udt = require('udt');
var fs = require('fs');

// check arguments
if (process.argv.length < 4) {
	console.log('Usage: node sendfile_clnt.js host-or-ip port\n');
	process.exit(-1);
}
var host = process.argv[2];
var port = parseInt(process.argv[3], 10);

var cln = udt.connect({port: port, host: host}, function(){
    console.log('UDP file client connected to '+host+':'+port);
    var file_stream = fs.createReadStream('./dummy/file_send.txt');
    
    file_stream.pipe(cln);
    
    // network performance monitor
    var npm = setInterval(function(){

    	var perf = cln.netPerf;

    	console.log('socket network Bandwidth       :'+JSON.stringify(perf.mbpsBandwidth)+' Mb/s');
    	console.log('socket network RTT             :'+JSON.stringify(perf.msRTT)+' ms');
    	console.log('socket network PktSndPeriod    :'+JSON.stringify(perf.usPktSndPeriod)+' us');
    	console.log('socket network SendRate        :'+JSON.stringify(perf.mbpsSendRate)+' Mb/s');
    	console.log('socket network RecvRate        :'+JSON.stringify(perf.mbpsRecvRate)+' Mb/s');
    	console.log('socket network CongestionWindow:'+JSON.stringify(perf.pktCongestionWindow));
    	console.log('socket network RecvACK         :'+JSON.stringify(perf.pktRecvACK));
    	console.log('socket network RecvNACK        :'+JSON.stringify(perf.pktRecvNAK));
    	console.log('socket network AvailRcvBuf     :'+JSON.stringify(perf.byteAvailRcvBuf));
    	console.log('socket network AvailSndBuf     :'+JSON.stringify(perf.byteAvailSndBuf)+'\n\n');

    }, 6000); // 6s
    
    // closure
    cln.on('end', function(){
        console.log('send file done');
        clearInterval(npm);
    });
});

