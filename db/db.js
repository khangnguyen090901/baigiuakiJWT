const mongoose = require('mongoose')

const connStr = 'mongodb+srv://khang:deanthuy@cluster0.3njuy.mongodb.net/myFirstDatabase?retryWrites=true&w=majority'

mongoose.set('debug', true)
mongoose
.connect(connStr, {
    useUnifiedTopology: true,
    useNewUrlParser: true,
})
.then(() => {
    console.log('Database is connected successfully!')
})
.catch(err => {
    console.log('Cannot connect to the database!', err)
    process.exit()
})