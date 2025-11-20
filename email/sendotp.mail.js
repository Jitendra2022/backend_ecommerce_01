import nodemailer from "nodemailer";
import "dotenv/config";
const sendOtpMail = async (otp, email) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });

  const mailConfiguration = {
    from: process.env.MAIL_USER,
    to: email,
    subject: "Password Reset Otp",
    html: `<p>Your OTP for password reset is:<b>${otp}</b></p>`,
  };

  transporter.sendMail(mailConfiguration, (error, info) => {
    if (error) {
      console.log("Error sending email:", error);
    } else {
      console.log("OTP sent successfully:", info.response);
    }
  });
};

export default sendOtpMail;
