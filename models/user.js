/** @format */

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = mongoose.Schema({
	firstName: {
		type: String,
		required: [true, "First Name is required"],
	},
	lastName: {
		type: String,
		required: [true, "Last Name is required"],
	},
	avatar: {
		type: String,
	},
	email: {
		type: String,
		required: [true, "Email is required"],
		validate: {
			validator: function (email) {
				return String(email)
					.toLowerCase()
					.match(
						/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
					);
			},
			message: "Email is invalid!",
		},
	},
	password: {
		type: String,
	},
	confirmPassword: {
		type: String,
	},
	passwordChangedAt: {
		type: Date,
	},
	passwordResetToken: {
		type: String,
	},
	passwordResetExpires: {
		type: Date,
	},
	createdAt: {
		type: Date,
	},
	updatedAt: {
		type: Date,
	},
	verified: {
		type: Boolean,
		default: false,
	},
	OTP: {
		type: Number,
	},
	OTPExpiryTime: {
		type: Date,
	},
});

userSchema.pre("save", async function (next) {
	if (!this.isModified("OTP") || !this.OTP) return next();

	this.OTP = await bcrypt.hash(this.OTP.toString(), 12);

	next();
});
userSchema.pre("save", async function (next) {
	if (!this.isModified("password") || !this.password) return next();

	this.password = await bcrypt.hash(this.password, 12);

	next();
});

userSchema.methods.correctPassword = async function (
	enteredPassword,
	originalPassword // hashed password
) {
	return await bcrypt.compare(enteredPassword, originalPassword);
};

userSchema.methods.correctOTP = async function (enteredOTP, originalOTP) {
	return await bcrypt.compare(enteredOTP, originalOTP);
};

userSchema.methods.createPasswordResetToken = function () {
	const resetToken = crypto.randomBytes(32).toString("hex");

	this.passwordResetToken = crypto
		.createHash("sha256")
		.update(resetToken)
		.digest("hex");

	this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

	return resetToken;
};

userSchema.methods.changedPasswordAfter = function (JWTTimeStamp) {
	if (this.passwordChangedAt) {
		const changedTimeStamp = parseInt(
			this.passwordChangedAt.getTime() / 1000,
			10
		);
		return JWTTimeStamp < changedTimeStamp;
	}
	return false;
};

const User = mongoose.model("User", userSchema);
module.exports = User;
