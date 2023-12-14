import React from 'react';
import '../Styles/NavBar2.css';
import { useNavigate } from 'react-router-dom';

const Navbar: React.FC = () => {
 const navigate = useNavigate();
 const text = globalThis.teacher ? "Join/Create class" : "Join Class";
 return (
    <div className="navbar">
      <button onClick={() => navigate('/')}>Home</button>
      <button onClick={() => navigate('/Login')}>Login</button>
      <button onClick={() => navigate('/JoinClass')}>{text}</button>
      <button onClick={() => navigate('/profile')}>Profile</button>
    </div>
  );
};

export default Navbar;