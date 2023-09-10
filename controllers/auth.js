/** @format */

const User = require("../models/user");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const crypto = require("crypto");

// Register -> SendOTP -> VerifyOTP

const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

exports.register = async (req, res, next) => {
	const { firstName, lastName, email, password } = req.body;

	const filteredObject = filterObj(
		req.body,
		"firstName",
		"lastName",
		"password",
		"email"
	);

	const exsistingUser = await User.findOne({ email: email });

	if (exsistingUser && exsistingUser.verified) {
		res.status(400).json({
			status: "error",
			message: "Email already in use.",
		});
		return;
	} else if (exsistingUser) {
		const updatedUser = await User.findOneAndUpdate(
			{ email: email },
			filteredObject,
			{ new: true, validateModifiedOnly: true }
		);
		req.userId = updatedUser._id;
		next();
	} else {
		const newUser = await User.create(filteredObject);
		req.userId = newUser._id;
		next();
	}
};

exports.verifyOTP = async (req, res, next) => {
	const { email, OTP } = req.body;

	const user = await User.findOne({
		email: email,
		OTPExpiryTime: { $gt: Date.now() },
	});

	if (!user) {
		res.status(400).json({
			status: "error",
			message: "Email incorrect or OTP has expired",
		});
	}

	if (!(await user.correctOTP(OTP, this.OTP))) {
		res.status(400).json({
			status: "error",
			message: "Incorrect OTP",
		});
	}
	user.verified = true;
	user.OTP = undefined;

	await user.save({ new: true, validateModifiedOnly: true });

	const token = signToken(user._id);

	res.status(200).json({
		status: "success",
		message: "Logged in successfully",
		token,
	});
};
exports.sendOTP = async (req, res, next) => {
	const { userId } = req;

	const newOTP = otpGenerator.generate(6, {
		lowerCaseAlphabets: false,
		upperCaseAlphabets: false,
		specialChars: false,
	});

	const otpExpiryTime = Date.now() + 10 * 60 * 1000;

	await User.findByIdAndUpdate(userId, {
		OTP: newOTP,
		OTPExpiryTime: otpExpiryTime,
	});

	// send email to user

	res.status(200).json({
		status: "success",
		message: "OTP sent successfully",
	});
};
exports.forgotPassword = async (req, res, next) => {
	const user = await User.findOne({ email: req.body.email });

	if (!user) {
		res.status(400).json({
			status: "error",
			message: "No user found with this email",
		});
		return;
	}

	const resetToken = user.createPasswordResetToken();
	const resetURL = `https://localhost:3000/auth/reset-password?code=${resetToken}`;

	try {
		res.status(200).json({
			status: "success",
			message: "Reset password URL sent successfully",
		});
	} catch (error) {
		user.passwordResetToken = undefined;
		user.passwordResetExpires = undefined;

		await user.save({ new: true, validateModifiedOnly: true });

		res.status(500).json({
			status: "error",
			message: "There was an error sending reset token on email",
		});
	}
};
exports.resetPassword = async (req, res, next) => {
	const hashedToken = crypto
		.createHash("sha256")
		.update(req.params.token)
		.digest("hex");

	const user = await User.findOne({
		passwordResetToken: hashedToken,
		passwordResetExpires: { $gt: Date.now() },
	});

	if (!user) {
		res.status(400).json({
			status: "error",
			message: "Token is invalid or expired",
		});
	}

	user.password = req.body.password;
	user.confirmPassword = req.body.confirmPassword;
	user.passwordResetToken = undefined;
	user.passwordResetExpires = undefined;

	await user.save();

	const token = signToken(user._id);

	res.status(200).json({
		status: "success",
		message: "Password reset successfully",
		token,
	});
};
exports.login = async (req, res, next) => {
	const { email, password } = req.body;

	if (!email || !password) {
		res.status(400).json({
			status: "error",
			message: "Email and Password are required",
		});
		return;
	}

	const user = await User.findOne({ email: email }).select("+password");

	if (!user || !(await user.correctPassword(password, user.password))) {
		res.status(400).json({
			status: "error",
			message: "Email or password is incorrect",
		});
		return;
	}

	const token = signToken(user._id);

	res.status(200).json({
		status: "success",
		message: "Logged in successfully",
		token,
	});
};
exports.protect = async (req, res, next) => {
	let token;
	if (
		req.headers.authorization &&
		req.headers.authorization.startsWith("Bearer")
	) {
		token = req.headers.authorization.split(" ")[1];
	} else if (req.cookies.jwt) {
		token = req.cookies.jwt;
	}
	if (!token) {
		return res.status(401).json({
			message: "You are not logged in! Please log in to get access.",
		});
	}
	const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

	const this_user = await User.findById(decoded.userId);
	if (!this_user) {
		return res.status(401).json({
			message: "The user belonging to this token does no longer exists.",
		});
	}
	if (this_user.changedPasswordAfter(decoded.iat)) {
		return res.status(401).json({
			message: "User recently changed password! Please log in again.",
		});
	}
	req.user = this_user;
	next();
};
