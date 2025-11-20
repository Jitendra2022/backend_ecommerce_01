import {
  forgotPassword,
  login,
  logout,
  register,
  reVerify,
  verify,
  verifyOtp,
} from "../controllers/user.controller.js";
import express from "express";
import isAuthenticated from "../middleware/isAuthenticated.js";
const router = express.Router();
router.post("/register", register);
router.post("/verify", verify);
router.post("/re-verify", reVerify);
router.post("/login", login);
router.post("/logout", isAuthenticated, logout);
router.post("/forgot-password", forgotPassword);
router.post("/verify-otp/:email", verifyOtp);
export default router;
