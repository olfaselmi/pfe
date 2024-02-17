const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({

    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    avatar: {
        type: String
    },
    resetToken: {
        type: String
    },
    expireToken: {
        type: Date,
    },
    tries: {
        type: Number,
        default: 0
    },
    suspended: {
        type: Date,
    },
    date: {
        type: Date,
        default: Date.now
    }
});
const User = mongoose.model('User', userSchema);

module.exports = User;