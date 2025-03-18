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

    // Email verification fields
    emailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: String,
    emailVerificationExpires: Date,

    // Password reset fields
    resetPasswordToken: String,
    resetPasswordExpires: Date,

    // MFA fields
    mfaEnabled: {
      type: Boolean,
      default: false,
    },
    mfaSecret: String,
    backupCodes: [
      {
        code: String,
        used: {
          type: Boolean,
          default: false,
        },
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.model("Pg33User", userSchema);
// B5C80315
// DB37FD5A
// 54BB8016
// 7AFAA35A
// C520EB52
// 907BA5D8
// 8A3B486D
// 6B148931
// 0FF8E19B
// 9A707417