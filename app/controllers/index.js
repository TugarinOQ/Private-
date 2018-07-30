let express = require("express"),
    router = express.Router(),
    Service = require('../servises/index'),
    service = new Service(),
    jwt = require('jsonwebtoken'),
    token__module = require("../token/index"),
    path = require('path');

router.use(function(req, res, next) {
    //middleware
    next();
});

router.post('/login', (req, res) => {
    const data = {
        token: jwt.sign({ username: req.body.username }, 'darkmarweblanser228'),
        username: req.body.username,
        password: req.body.password
    };
    service.auth(data,
        function(success, status) {
            res.status(status).json(success);
        },
        function(err, status) {
            res.status(status).json(err);
        });
});

router.post('/dialogs.get', token__module.isValid, (req, res) => {
    service.getDialogs(req, function(success) {
        res.status(200).json(success);
    },
    function(err, status) {
        res.status(status).json(err);
    });
});

module.exports = router;