const mongoose = require("mongoose");

const jobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  company: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Pg33User",
    required: true,
  },
  location: String,
  description: String,
  salary: Number,
  employmentType: {
    type: String,
    enum: ["full-time", "part-time", "contract"],
    default: "full-time",
  },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Pg33Job", jobSchema);
