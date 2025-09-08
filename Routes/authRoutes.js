// routes/authRoutes.js
import express from "express";
import {
  getProfile,
  login,
  logout,
  refreshToken,
  signup,
  verifyEmail,
} from "../Controller/authController.js";
import {
  authMiddleware,
  authorizeRoles,
  loginLimiter,
} from "../Middleware/authMiddleware.js";

const router = express.Router();

// Placeholder routes
router.post("/signup", signup);
router.get("/verify-email", verifyEmail);
router.post("/login", loginLimiter, login);

router.post("/logout", logout);

router.get("/profile", authMiddleware, getProfile);

router.post("/refresh-token", refreshToken);

// Only admins
router.get("/admin", authMiddleware, authorizeRoles("admin"), (req, res) => {
  res.json({ msg: "Welcome Admin!", user: req.user });
});
export default router;
