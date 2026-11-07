const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

// REMOVED 'next' parameter since it's an async function
UserSchema.pre('save', async function () {
    if (!this.isModified('password')) return; // Just return instead of next()

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    // No next() call needed here anymore
});

module.exports = mongoose.model('User', UserSchema);
