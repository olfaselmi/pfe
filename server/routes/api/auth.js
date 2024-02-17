const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../../mongodb/models/user");
const { check, validationResult } = require("express-validator");
const router = express.Router();
const bcrypt = require("bcryptjs");
const authMiddleware = require("../../middleware/authMiddleware");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const sendgridTransport = require("nodemailer-sendgrid-transport");
const saltRounds = 10;


const transporter = nodemailer.createTransport(
    sendgridTransport({
        auth: {
            api_key: "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",
        },
    })
);

//@author Olfa selmi
//@Route GET api/auth
//@Description  This is a test route
//@Access Public
router.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(400).json({ message: "User not found!" });
        }






        if (user.tries >= 3) {
            if (user.suspended < Date.now() || user.suspended === null) {
                user.tries = 0;
                user.suspended = ""
                await user.save()
            } else {
                return res.status(400).json({ message: "Account still suspended!" });

            }
            user.suspended = Date.now() + 1 * 60 * 1000
            await user.save()
            return res.status(400).json({ message: "Account suspended!" });

        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            user.tries = user.tries + 1;
            await user.save()
            return res.status(400).json({ message: "Wrong password!" });
        }
        const payload = { user: { id: user.id, email: user.email } };
        const jwToken = jwt.sign(payload, "this a secret key"); // Replace with your secret key
        return res.status(200).json({
            message: "User connected!",
            user: {
                id: user._id,
                email: user.email,
                avatar: user.avatar,
            },
            token: jwToken,
        });
    } catch (error) {
        console.error(error.message);
        return res.status(500).send("Server error");
    }
});

//@author Olfa Selmi
//@Route POST api/auth/reset-password
// @Description  Reset your password route
// @Access Public
router.post(
    "/reset-password",
    [check("email", "Please enter a valid email").isEmail()],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { email } = req.body;

        try {
            const token = crypto.randomBytes(32).toString("hex");
            let user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({ message: "User not found, try again!" });
            }
            user.resetToken = token;
            user.expireToken = Date.now() + 3600000;

            const payload = { resetToken: { email: email, token: token } };
            const jwToken = jwt.sign(payload, "this a secret key"); // Replace with your secret key

            await user.save();

            await transporter.sendMail({
                to: user.email,
                from: "olfa.selmi@esprit.tn",
                subject: "Did you forget your password?",
                html: `
                <p>You requested for a password reset</p>
                <h5>Click on this 
                <a href="http://localhost:3000/auth-changepassword?token=${jwToken}">
                link
                </a> to reset your password
                </h5>
                `,
            });

            return res.json({ message: "Email sent successfully! Please check your email." });
        } catch (error) {
            console.error(error.message);
            return res.status(500).send("Server error");
        }
    }
);

//@author Olfa Selmi
//@Route POST api/auth/new-password
// @Description  New password route
// @Access Public
router.post(
    "/new-password",
    [
        check(
            "newPassword",
            "Please enter a password with at least 6 characters"
        ).isLength({
            min: 6,
        }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const newPassword = req.body.newPassword;
            const sentToken = req.body.sentToken;

            if (!sentToken) {
                return res.status(400).json({
                    errors: [{
                        message: "You need to send an email in order to change your password",
                    }],
                });
            }

            const user = await User.findOne({
                resetToken: sentToken,
                expireToken: { $gt: Date.now() },
            });

            if (!user) {
                return res.status(400).json({
                    errors: [{
                        message: "Session has been expired, please resend another 'Forgot your password' email",
                    }],
                });
            }

            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(newPassword.toString(), salt);
            user.resetToken = "";
            user.expireToken = "";
            await user.save();
            return res.json({ message: "Password updated successfully" });
        } catch (error) {
            console.error(error.message);
            return res.status(500).send("Server error");
        }
    }
);

//@author Olfa Selmi
//@Route POST api/auth/change-password
// @Description  Change password 
// @Access Private  
router.post(
    '/change-password',
    [
        check('email', 'Please enter a valid email').isEmail(),
        check('password', 'Password is required').exists(),
    ],
    authMiddleware,
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { oldPassword, password } = req.body;
        const user = await User.findById(req.userId);
        try {
            const isMatch = await bcrypt.compare(oldPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ errors: [{ message: 'Invalid parameters, try again!' }] });
            }
            const salt = await bcrypt.genSalt(saltRounds);
            user.password = await bcrypt.hash(password, salt);
            await user.save();
            return res.json({ message: "Password changed successfully" });
        } catch (error) {
            console.error(error.message);
            return res.status(500).send('Server error');
        }
    }
);

module.exports = router;
