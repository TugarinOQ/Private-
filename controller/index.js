let express = require("express"),
    router = express.Router();

router.post('/login', (res, req) => {
    let data = {
        login: login,
        password: pass,
        stor_login: store
    }
    res.json(JSON.stringify(data));
});