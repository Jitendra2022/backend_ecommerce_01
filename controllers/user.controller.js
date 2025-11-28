import { User } from "../models/user.model.js";
import bcrypt from "bcrypt";
import "dotenv/config";
import jwt from "jsonwebtoken";
import verifyEmail from "../email/email.verify.js";
import { Session } from "../models/session.model.js";
import sendOtpMail from "../email/sendotp.mail.js";
const register = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    if (!firstName || !lastName || !email || !password) {
      res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }
    const user = await User.findOne({ email });
    if (user) {
      res.status(400).json({
        success: false,
        message: "User allready exists",
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
    });
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });
    verifyEmail(token, email);
    newUser.token = token;
    await newUser.save();
    return res.status(201).json({
      success: true,
      message: "User registred successfully",
      user: newUser,
    });
  } catch (e) {
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};
const verify = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, decoded) => {
      if (err) {
        if (err.name === "TokenExpiredError") {
          return res.status(401).json({ message: "Token has expired" });
        }
        return res.status(403).json({ message: "Invalid token" });
      }

      const userId = decoded.id;

      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // NEW: If user is already verified
      if (user.isVerified) {
        return res.status(200).json({
          message: "User is already verified",
          user: {
            id: user._id,
            email: user.email,
            isVerified: user.isVerified,
          },
        });
      }

      // If not verified, verify the user
      user.token = null;
      user.isVerified = true;
      await user.save();

      return res.status(200).json({
        message: "Email verified successfully",
        success:true,
        user: {
          id: user._id,
          email: user.email,
          isVerified: user.isVerified,
        },
      });
    });
  } catch (error) {
    return res.status(500).json({ message: "Server error", error });
  }
};

const reVerify = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // If already verified, no need to send again
    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "User is already verified",
      });
    }

    // Create new verification token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    // Save token in DB
    user.token = token;
    await user.save();

    // Send verification email
    await verifyEmail(token, email);

    return res.status(200).json({
      success: true,
      message: "Verification email sent again successfully",
      token: token,
    });
  } catch (error) {
    console.error("Re-verify error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "all fields are required",
      });
    }
    const exisitingUser = await User.findOne({ email });
    if (!exisitingUser) {
      return res.status(400).json({
        success: false,
        message: "user not found",
      });
    }
    const isPasswordValid = await bcrypt.compare(
      password,
      exisitingUser.password
    );
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "invalid credential",
      });
    }
    if (exisitingUser.isVerified === false) {
      return res.status(400).json({
        success: false,
        message: "verify your account than login",
      });
    }
    const accessToken = jwt.sign(
      { id: exisitingUser._id },
      process.env.JWT_SECRET_KEY,
      {
        expiresIn: process.env.JWT_EXPIRES_IN,
      }
    );
    const refreshToken = jwt.sign(
      { id: exisitingUser._id },
      process.env.JWT_SECRET_KEY,
      {
        expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
      }
    );
    // Update the isLoggedIn flag
    if (!exisitingUser.isLoggedIn) {
      exisitingUser.isLoggedIn = true;
      await exisitingUser.save();
    }
    const exisitingSession = await Session.findOne({
      userId: exisitingUser._id,
    });
    // check for exisiting session and delete it
    if (exisitingSession) {
      await Session.deleteOne({ userId: exisitingUser._id });
    }
    // create a new session
    await Session.create({ userId: exisitingUser._id });
    return res.status(200).json({
      success: true,
      message: `Welcome back  ${exisitingUser.firstName}`,
      user: exisitingUser,
      accessToken,
      refreshToken,
    });
  } catch (error) {}
};
const logout = async (req, res) => {
  try {
    const userId = req.id;
    await Session.deleteMany({ userId: userId });
    await User.findByIdAndUpdate(userId, { isLoggedIn: false });
    return res.status(200).json({
      success: true,
      message: "user logged out successfully",
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // OTP expires in 10 minutes
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    // Send OTP email
    await sendOtpMail(otp, email);

    return res.status(200).json({
      success: true,
      message: "OTP sent to email successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Something went wrong",
      error: error.message,
    });
  }
};
const verifyOtp = async (req, res) => {
  try {
    const { otp } = req.body;
    const email = req.params.email;
    if (!otp) {
      return res.status(400).json({
        success: false,
        message: "otp is REQUIRED",
      });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "user not found",
      });
    }
    if (!user.otp || !user.otpExpiry) {
      return res.status(400).json({
        success: false,
        message: "otp is not generated or already verified",
      });
    }
    if (user.otpExpiry < new Date()) {
      return res.status(400).json({
        success: false,
        message: "otp has expired please request a new one",
      });
    }
    if (otp !== user.otp) {
      return res.status(400).json({
        success: false,
        message: "invalid otp",
      });
    }
    user.otp = null;
    user.otpExpiry = null;
    await user.save();
    return res.status(200).json({
      success: true,
      message: "otp verified sccessfull",
    });
  } catch (error) {}
};
export { register, verify, reVerify, login, logout, forgotPassword, verifyOtp };
