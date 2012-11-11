var http = require('http');

http.get('http://localhost:51688', function(res){
//http.get('http://192.168.1.106:51688', function(res){
   console.log('STATUS: ' + res.statusCode);
   console.log('HEADERS: ' + JSON.stringify(res.headers));
   res.on('data', function (chunk) {
   console.log('BODY: ' + chunk);
  });
});
