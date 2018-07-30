var express    = require('express');
var app        = express();
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var cookieParser = require('cookie-parser');

mongoose.connect('mongodb://darkmars:weblanser228@ds219100.mlab.com:19100/cookies', { useNewUrlParser: true }, function(err) {
    if (err) throw new Error("Connection error: ", err.message);
    app.listen(2521, () => {
        console.log("Server started on 2521 port");
    });
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.text({ type: 'text/html' }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use('/api', require('./app/controllers/index'));