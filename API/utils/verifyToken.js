import jwt from "jsonwebtoken";
import { createError } from "../utils/error.js";

export const verifyToken = (req, res, next) => {
    const token = req.cookies.access_token
    if(!token){
        return next(createError(401, "Not authorized"))
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user)=>{
        if(err) return next(createError(403, "Invalid token"));
        req.user = user;
        next()
    })
}

export const verifyUser = (req, res, next) => {
    verifyToken(req, res, (error) => {
        if (error) return next(error); 

        if (!req.user) {
            return next(createError(403, "Authorization failed, user data missing"));
        }

        if (req.user.id === req.params.id || req.user.isAdmin) {
            return next();
        }

        return next(createError(403, "You are not authorized!"));
    });
};

export const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, (error) => {
        if (error) return next(error); 

        if (!req.user) {
            return next(createError(403, "Authorization failed, user data missing"));
        }

        if (req.user.isAdmin) {
            return next();
        }

        return next(createError(403, "You are not authorized!"));
    });
};