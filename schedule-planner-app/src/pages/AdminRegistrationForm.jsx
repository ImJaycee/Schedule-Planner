import { useState } from "react";
import axios from "axios";
import logo from "../assets/a2klogo.png";
import logoApp from "../assets/logo.png";

const RegisterForm = () => {
  const [formData, setFormData] = useState({
    firstname: "",
    lastname: "",
    email: "",
    department: "",
    password: "",
    confirmPassword: "",
    isAdmin: true,
  });

  const [errors, setErrors] = useState({});

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    let validationErrors = {};

    if (!formData.firstname) validationErrors.firstname = "First name is required";
    if (!formData.lastname) validationErrors.lastname = "Last name is required";
    if (!formData.email.includes("@")) validationErrors.email = "Valid email is required";
    if (!formData.department) validationErrors.department = "Department is required";
    if (formData.password.length < 8) validationErrors.password = "Password must be at least 8 characters";
    if (formData.password !== formData.confirmPassword)
      validationErrors.confirmPassword = "Passwords do not match";

    if (Object.keys(validationErrors).length === 0) {
      try {
        const response = await axios.post("http://localhost:4000/api/auth/register", formData, {
          headers: { "Content-Type": "application/json" },
        });
  
        if (response.status === 200) {
          alert("Register successfully");
          console.log(formData);
        }
      } catch (error) {
        console.error("Error:", error);
        alert("Fail to register");
      }
    } else {
      setErrors(validationErrors);
    }
  };

  return (
    <div className="relative flex flex-col items-center justify-center min-h-screen bg-gray-100">
          {/* Left Logo */}
          <img src={logo} alt="Logo" className="absolute top-4 left-4 w-32 h-32" />
    
          {/* Right Logo */}
          <img src={logoApp} alt="Logo" className="absolute top-4 right-4 w-32 h-32" />
    
      <div className="w-full max-w-md">
        <div className="w-full max-w-md">
          <h2 className="text-2xl font-bold mb-2 text-left">Create admin account</h2> 
          <div className="p-8 bg-white rounded-lg shadow-md">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-700">Firstname</label>
                  <input
                    type="text"
                    name="firstname"
                    placeholder="Firstname"
                    value={formData.firstname}
                    onChange={handleChange}
                    className="p-2 border rounded w-full"
                  />
                  {errors.firstname && <p className="text-red-500 text-sm">{errors.firstname}</p>}
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-700">Lastname</label>
                  <input
                    type="text"
                    name="lastname"
                    placeholder="Lastname"
                    value={formData.lastname}
                    onChange={handleChange}
                    className="p-2 border rounded w-full"
                  />
                  {errors.lastname && <p className="text-red-500 text-sm">{errors.lastname}</p>}
                </div>
              </div>

              <div>
                <label className="text-sm font-medium text-gray-700">Email</label>
                <input
                  type="email"
                  name="email"
                  placeholder="Enter Email"
                  value={formData.email}
                  onChange={handleChange}
                  className="p-2 border rounded w-full"
                />
                {errors.email && <p className="text-red-500 text-sm">{errors.email}</p>}
              </div>

              <div>
                <label className="text-sm font-medium text-gray-700">Department</label>
                <select
                  name="department"
                  value={formData.department}
                  onChange={handleChange}
                  className="p-2 border rounded w-full"
                >
                  <option value="">Select Department</option>
                  <option value="Technical">Technical</option>
                  <option value=" IT Support">IT Support</option>
                  <option value="Sales & Marketing">Sales & Marketing</option>
                  <option value="Research">Research</option>
                </select>
                {errors.department && <p className="text-red-500 text-sm">{errors.department}</p>}
              </div>


              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-700">Password</label>
                  <input
                    type="password"
                    name="password"
                    placeholder="Password"
                    value={formData.password}
                    onChange={handleChange}
                    className="p-2 border rounded w-full"
                  />
                  {errors.password && <p className="text-red-500 text-sm">{errors.password}</p>}
                </div>

                <div>
                  <label className="text-sm font-medium text-gray-700">Confirm Password</label>
                  <input
                    type="password"
                    name="confirmPassword"
                    placeholder="Confirm Password"
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    className="p-2 border rounded w-full"
                  />
                  {errors.confirmPassword && <p className="text-red-500 text-sm">{errors.confirmPassword}</p>}
                </div>
              </div>

              <button type="submit" className="w-full bg-blue-500 text-white py-2 rounded">
                Register
              </button>

            </form>
            <p className="text-center text-sm mt-4">
              Already have an <a href="/" className="text-blue-500">account?</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RegisterForm;
