const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cookieParser());

mongoose
  .connect(process.env.DB_URL)
  .then(() => console.log("Database connected Successfully"))
  .catch((err) => console.log("Connection Failed"));

const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized: Token not found" });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, verifyy) => {
    if (err) {
      return res.status(403).json({ message: "Token Invalid" });
    }
    req.user = verifyy;
    next();
  });
};

app.post("/auth", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(404).json({ message: "Invalid Credentials" });
      }
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      user = new User({ username, email, password: hashedPassword });
      await user.save();
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "15m"
    });
    res.cookie("token", token, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    return res.json("Authentication successful");
  } catch (err) {
    return res.status(500).json({ error: "Authentication Failed" });
  }
});

app.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
      res.json(user);
  } catch (err) {
    return res.status(500).json({ error: "Server Error" });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.json("Logged out Successfully");
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
