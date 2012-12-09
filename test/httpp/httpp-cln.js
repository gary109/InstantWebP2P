var httpp = require('httpp');

for (var i = 0; i < 200; i ++)
httpp.get('http://localhost:8000', function(res){
   console.log('STATUS: ' + res.statusCode);
   console.log('HEADERS: ' + JSON.stringify(res.headers));
   res.on('data', function (chunk) {
   console.log('BODY: ' + chunk);
  });
});

