var httpp = require('httpp');

httpp.get('http://localhost:51688', function(res){
   console.log('STATUS: ' + res.statusCode);
   console.log('HEADERS: ' + JSON.stringify(res.headers));
   res.on('data', function (chunk) {
   console.log('BODY: ' + chunk);
  });
});

httpp.get('http://localhost:51866', function(res){
   console.log('STATUS: ' + res.statusCode);
   console.log('HEADERS: ' + JSON.stringify(res.headers));
   res.on('data', function (chunk) {
   console.log('BODY: ' + chunk);
  });
});
