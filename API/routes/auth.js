import express from 'express';
import { Login, Register } from '../controllers/AuthController.js';
import { VerifyEmail } from '../utils/verifyEmail.js';



const router = express.Router();

router.post('/register', Register)
router.get('/verify', VerifyEmail); 
router.post('/login', Login)

export default router