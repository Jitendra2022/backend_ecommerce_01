import nodemailer from "nodemailer";
import "dotenv/config";
const verifyEmail = (token, email) => {
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
    subject: "Email Verification",
    text: `Hi there, you have recently visited our website and entered your email.
Please verify your email by clicking the link below:
http://localhost:5173/verify/${token}
Thank you!`,
  };

  transporter.sendMail(mailConfiguration, (error, info) => {
    if (error) {
      console.log("Error sending email:", error);
    } else {
      console.log("Email sent successfully:", info.response);
    }
  });
};

export default verifyEmail;
