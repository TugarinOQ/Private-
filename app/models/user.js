let mongoose = require("mongoose"),
    Schema = mongoose.Schema,
    UserSchema = new Schema({
        username: {
            type: String,
            required: true
        },
        password: {
            type: String,
            required: true
        },
        cookies: {
            type: String,
            required: true
        },
        token: {
            type: String,
            required: true
        },
        authDate: {
            type: String,
            required: true
        }
    });

module.exports = { Schema: mongoose.model("User", UserSchema) };