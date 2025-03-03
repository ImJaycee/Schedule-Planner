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
        const user = await User.findOne({username: req.body.username})
        if (!user) return next(createError(404, "User not found"))

        const passwordCorrect = await bcrypt.compare(req.body.password, user.password);
        if(!passwordCorrect) 
            return next(createError(400, "Incorrect password"));

        const token = jwt.sign({id: user._id, isAdmin: user.isAdmin}, process.env.JWT_SECRET);
        
        const userDetails = user.toObject ? user.toObject() : user;

        const { password, isAdmin, ...otherDetails } = userDetails; 

        res.cookie("access_token", token, {
            httpOnly: true,
        })
        .status(200)
        .json(otherDetails);
    } catch (err) {
     next(err);
    }
 };