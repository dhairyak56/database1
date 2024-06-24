const mongoose = require('mongoose');

const EventSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  organization: {
    type: String,
    required: true,
  },
  location: {
    type: String,
    required: true,
  },
  time: {
    type: Date,
    required: true,
  },
});

module.exports = mongoose.model('Event', EventSchema);
