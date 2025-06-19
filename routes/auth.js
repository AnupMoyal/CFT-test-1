const express = require("express");
const {
  register, login, getUser,
  forgotPassword, resetPassword
} = require("../controllers/authController");

const router = express.Router();
const auth = require("../middleware/auth");

router.post("/signup", register);
router.post("/login", login);
router.get("/me", auth, getUser);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

module.exports = router;
