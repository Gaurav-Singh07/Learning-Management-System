import { User } from "../modals/user.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sendMail from "../middlewares/sendMail.js";
import TryCatch from "../middlewares/TryCatch.js";

export const register = async (req, res) => {
  try {
    const { email, name, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User Already Exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
    });

    await user.save();
    const otp = Math.floor(100000 + Math.random() * 900000); // Always 6-digit OTP

    const activationToken = jwt.sign(
      {
        user,
        otp,
      },
      process.env.Activation_secret,
      { expiresIn: "1d" }
    );

    const data = {
      name,
      otp,
    };

    await sendMail(email, "E-learning OTP Verification", data);

    res.status(200).json({
      message: "OTP sent to your email",
      activationToken,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const verifyUser = TryCatch(async (req, res) => {
  const { otp, activationtoken } = req.body;

  const verify = jwt.verify(activationtoken, process.env.Activation_secret);

  if (!verify) {
    return res.status(400).json({
      message: "Otp expired",
    });
  }

  if (verify.otp != otp) {
    return res.status(400).json({
      message: "Wrong Otp",
    });
  }

  await User.create({
    name: verify.user.name,
    email: verify.user.email,
    password: verify.user.password,
  });

  res.json({
    message: "User registered",
  });
});

export const loginUser = TryCatch(async (req, res) => {
  const { email, password } = req.body;

  // console.log("Login Request Body:", req.body);

  const user = await User.findOne({ email: email.toLowerCase() });

  console.log("User Found:", user);

  if (!user) {
    return res.status(400).json({ message: "User not login" });
  }

  const matchPassword = await bcrypt.compare(password, user.password);
  console.log("Password Match:", matchPassword);

  if (!matchPassword) {
    return res.status(400).json({ message: "Invalid Credentials" });
  }

  const token = jwt.sign({ _id: user._id }, process.env.Jwt_Sec, {
    expiresIn: "15d",
  });

  res.json({
    message: `Welcome back ${user.name}`,
    token,
    user,
  });
});

export const myProfile = TryCatch(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  res.status(200).json({ user });
});
