import { useState } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { AuthContextProvider } from "./context/AuthContext";
import ProtectedRoutes from './utils/ProtectedRoutes';
import RegisterForm from './pages/RegistrationForm';
import AdminRegistrationForm from './pages/AdminRegistrationForm';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard' 




function App() {
  return (
    <AuthContextProvider> {/* */}
    <Router>
        <Routes>
            {/* Public Routes */}
            <Route path="/" element={<Navigate to="/login" />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<RegisterForm />} />
            <Route path="/admin/register" element={<AdminRegistrationForm />} />

            {/* protected routes*/}
            <Route element={<ProtectedRoutes />}>
                <Route path="/homepage" element={<Dashboard />} />
            </Route>

        </Routes>
    </Router>
</AuthContextProvider>
  );
}
// Welcome Page Component
function Welcome() {
  return (
    <div className="flex justify-center items-center min-h-screen bg-gray-100">
      <div className="p-6 bg-white shadow-md rounded-lg text-center">
        <h2 className="text-2xl font-bold mb-4">Welcome</h2>
        <p className="text-gray-600 mb-4">Login to your account or register.</p>
        <a
          href="/login"
          className="w-32 bg-blue-500 text-white px-4 py-2 rounded inline-block"
        >
          Login
        </a>
        <p className="text-gray-600 m-2">or</p>
        <a
          href="/register"
          className="w-32 bg-blue-500 text-white px-4 py-2 rounded inline-block"
        >
          Register
        </a>
      </div>
    </div>
  );
}

export default App
