import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { createError } from '../utils/error.js';

dotenv.config()

const accessToken = process.env.JWT_SECRET


export const Register = async(req, res, next) => { 
   try {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);

        const newUser = new User({
            firstname: req.body.firstname,
            lastname: req.body.lastname,
            email: req.body.email,
            department: req.body.department,    
            password: hash,
            isAdmin: req.body.isAdmin || false
        })

        await newUser.save()
        res.status(200).send("User created successfully")
   } catch (error) {
    next(error);
   }
};

export const Login = async(req, res, next) => { 
    try {
        const user = await User.findOne({email: req.body.email})
        if (!user) return next(createError(404, "User not found"))

        const passwordCorrect = await bcrypt.compare(req.body.password, user.password);
        if(!passwordCorrect) 
            return next(createError(400, "Incorrect password"));

        const token = jwt.sign({id: user._id, isAdmin: user.isAdmin}, process.env.JWT_SECRET);
        
        const userDetails = user.toObject ? user.toObject() : user;

        const { password, isAdmin, ...otherDetails } = userDetails; 

        console.log(otherDetails);

        res.cookie("access_token", token, {
            httpOnly: true,
        })
        .status(200)
        .json(otherDetails);
    } catch (err) {
     next(err);
    }
 };



// export const Login = async (req, res) => {
//     try {

//       const { email, password } = req.body;
  
//       console.log("Login attempt for:", email); // Debugging log
  
//       // Find user by email
//       const user = await User.findOne({ email });
//       if (!user) {
//         console.log("User not found!");
//         return res.status(404).json({ success: false, message: "User not found" });
//       }
  
//       // Compare password
//       const isMatch = await bcrypt.compare(password, user.password);
//       if (!isMatch) {
//         console.log("Wrong password!");
//         return res.status(401).json({ success: false, message: "Wrong password" });
//       }
  
//       // Generate JWT token
//       const token = jwt.sign(
//         { id: user._id, isAdmin: user.isAdmin },
//         process.env.JWT_SECRET,
//         { expiresIn: "1h" }
//       );
  
//       console.log("Token generated:", token); // Debugging token
  
//       // Remove sensitive details before sending response
//       const { password: _, isAdmin, ...otherDetails } = user.toObject();

//       console.log(otherDetails);


//       return res.status(200).json({
//         success: true,
//         token,
//         user: { _id: user._id, name: user.name, role: user.role, details: otherDetails }
//       });
  
//     } catch (error) {
//       console.error("Login Error:", error);
//       return res.status(500).json({ success: false, message: "Server error" });
//     }
// };
