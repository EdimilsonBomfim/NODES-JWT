const mongoose = require('mongoose')

const User = mongoose.model('User', {
    name: String, 
    email: String,
    password: String,
})

//Exportar o module
module.exports = User
