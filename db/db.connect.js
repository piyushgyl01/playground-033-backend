const mongoose = require("mongoose");
require("dotenv").config();

const MONGOURI = process.env.MONGODB;

async function connectToDB() {
  mongoose
    .connect(MONGOURI)
    .then(() => {
      console.log(`CONNECTED TO DB`);
    })
    .catch((e) => {
      console.log("Error occured while connecting to DB", e);
    });
}

module.exports = { connectToDB };
