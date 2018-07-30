let bcrypt = require('bcrypt-nodejs');

module.exports = function() {
    self = this;

    self.hashPassword = function(data, cbSuccess) {
        const user = data;
        if (data.password !== undefined && data.password.length !== 0) {
            if (!checkRegExPassword(data.password)) return cbError({ error: "Incorrect password" }, 400);
            bcrypt.genSalt(5, function(err, salt) {
                if (err) {
                    return;
                }

                bcrypt.hash(user.password, salt, null, function(err, hash) {
                    if (err) {
                        return;
                    }
                    user.password = hash;
                    cbSuccess(user);
                });
            });
        } else {
            cbSuccess(user);
        }
    };

    self.rebuildUserData = function(userData) {
        let user = {
            id: userData._id,
            username: userData.username,
            token: userData.token,
            // cookies: userData.cookies,
            authDate: userData.authDate
        };

        return user;
    }

    function checkRegExPassword(pass) {
        return /^[a-z0-9A-Z](?=.*[\d])(?=.*[a-z]).{8,}$/.test(pass) && pass.length > 7;
    }
}