const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: function () {
        return !this.googleId && !this.githubId;
      },
      unique: true,
      sparse: true,
    },
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      unique: true,
      sparse: true,
    },
    password: {
      type: String,
      required: function () {
        return !this.googleId && !this.githubId;
      },
    },
    googleId: {
      type: String,
      unique: true,
      sparse: true,
    },
    githubId: {
      type: String,
      unique: true,
      sparse: true,
    },
    avatar: {
      type: String,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Pg33User", userSchema);
