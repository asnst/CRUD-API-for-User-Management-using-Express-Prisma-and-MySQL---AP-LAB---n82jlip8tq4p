import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../prismaClient.js";

export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });
    if (!password) return res.status(400).json({ error: "Password is required" });

    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) return res.status(400).json({ error: "Email already in use" });

    
    const hashed = await bcrypt.hash(password, Number(process.env.BCRYPT_SALT));

    const user = await prisma.user.create({
      data: { name, email, password: hashed },
    });

    return res.status(201).json({
      message: "User created successfully",
      userId: user.id,
    });

  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

   
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user)
      return res.status(404).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.status(200).json({
      userdata: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
      accesstoken: token,
    });

  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
};
