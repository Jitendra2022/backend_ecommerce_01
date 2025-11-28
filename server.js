import express from "express";
import "dotenv/config";
import morgan from "morgan";
import cors from "cors";
import connectDB from "./database/db.js";
import userRoute from "./routes/user.route.js";
const app = express();
const PORT = process.env.PORT || 8080;
// Connect to MongoDB
connectDB();
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));
app.use("/api/v1/user", userRoute);
// Root route FIRST
app.get("/", (req, res) => {
  res.send("🚀 API is running...");
});
app.listen(PORT, () => {
  console.log(`server is listning at port:http://localhost:${PORT}`);
});
