import express from 'express';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import authRoute from './routes/auth.js';
import userRoute from './routes/userRoute.js';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const app = express();
dotenv.config();

const PORT = process.env.PORT
const MONGO_URL = process.env.MONGO_URL

const connect = async () =>{
    try {
        await mongoose.connect(MONGO_URL);
        console.log('Connected to MongoDB');
    }catch(e) {
       throw e
    }
}
//middlewares
app.use(cookieParser());

app.use(express.json())
app.use(cors())


//routes
app.use("/api/auth", authRoute);
app.use("/api/user", userRoute);


app.use((err, req, res, next) =>{
    const errorStatus = err.status || 500
    const errorMessage = err.message || "Something went wrong!"
    return res.status(errorStatus).json({
        success: false,
        status: errorStatus,
        message: errorMessage,
        stack: err.stack
    })
 })


app.listen(4000, () => {
    connect();
    console.log(`Listening on port 4000`)
  })
