import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {fetch2} from '../endpointFunction';

const Register: React.FC = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('');

  const handleUsernameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setUsername(event.target.value);
  };

  const handlePasswordChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  };

  const handleRoleChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    setRole(event.target.value);
  };

  const handleRegister = async (): Promise<void> => {
    const response = await fetch2('/register','POST',{"email":username,"password":password,"role": role === "teacher"});
    const ret = await response.json().then(ret => {return ret;});
    console.log(ret);
    if (response.ok) {
    globalThis.userName = username;
    globalThis.password = password;
    globalThis.teacher = role === "teacher";
    navigate('/');
    }
    else {console.log("failed");}
  };

  return (
    <div>
      <h2>Register</h2>
      <form onSubmit={(e) => {
        e.preventDefault(); // Prevent form submission (for this example)
        handleRegister();
      }}>
        <div>
          <label htmlFor="username">Username:</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={handleUsernameChange}
          />
        </div>
        <div>
          <label htmlFor="password">Password:</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={handlePasswordChange}
          />
        </div>
        <div>
          <label htmlFor="role">Role:</label>
          <select id="role" value={role} onChange={handleRoleChange}>
            <option value="">Select Role</option>
            <option value="teacher">Teacher</option>
            <option value="student">Student</option>
          </select>
        </div>
        <div>
          <button type="submit">Register</button>
        </div>
      </form>
    </div>
  );
};

export default Register;