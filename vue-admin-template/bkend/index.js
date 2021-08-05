const express = require('express')
const bodyParser = require('body-parser')
const app = express()
app.use(bodyParser.json())

var options = {
    mode: 'text',
    pythonPath: '/usr/bin/python3',
    pythonOptions: ['-u'], 
    scriptPath: '../',
    args: ['../goap/actions-it.json'] 
};


//Disable CORS
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});


app.get('/api', function(req, res) {

  var {PythonShell} = require('python-shell');
  //var pyshell = new PythonShell('main.py',options);  
  PythonShell.run('main.py',options,function(err) {
    if (err) throw err;
    console.log('finished');
  });
  console.log("req")
  console.log(req.query.data) //Display data from the frontend in console.log
  pyshell.send(req.query.data);  
  pyshell.on('message',  function (data) {
    console.log("return data")
    res.send({
      message: data   //Return the result of the operation to the frontend
    })
  })

})

console.log("Start API Server for IT")
app.listen(3000)
