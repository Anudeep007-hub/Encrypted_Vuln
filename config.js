const mariadb = require("mariadb");

const pool = mariadb.createPool({
    host: "localhost", 
    user: "root", 
    password: "123",
    database: "app"
});

module.exports = pool;