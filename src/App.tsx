import React from 'react';
import {Route, Routes, Navigate, BrowserRouter as Router} from 'react-router-dom';
import MainPage from "./Pages/MainPage";
import NavBar from "./NavBar/NavBar";
import NavBar2 from "./NavBar/NavBar2";
import Login from "./Pages/Login";
import Login2 from "./Pages/Login2";
import Signup from "./Pages/Signup";
import Register from "./Pages/Register";
import CreateClass from "./Pages/CreateClass"
import UnavailableTime from "./Pages/UnavailableTime"
import Profile from "./Pages/Profile"
import JoinClass from "./Pages/JoinClass"
import ManageClasses from "./Pages/ManageClasses"
import './App.css';
import CourseManager from './Pages/CourseManager';

//main app componant, called by index as the app render, sets all the routes of the app to their corresponding page
//displays the nav bar
function App() {
  return (
    <Router> 
      <div className = "App"> 

        <header>
          <NavBar2/>
        </header>

        <br/>
        
        <Routes>
          <Route path = '/' element={<MainPage/>}/>
          <Route path = '/Home' element={<MainPage/>}/>
          <Route path = '/JoinClass' element={<JoinClass/>}/>
          <Route path = '/Profile' element={<Profile/>}/>
          <Route path = '/CreateClass' element={<CreateClass/>}/>
          <Route path = '/UnavailableTime' element={<UnavailableTime/>}/>
        </Routes>
        <Routes>
          <Route path = '/login' element={<Login2/>}/>
        </Routes>
        <Routes>
          <Route path = '/signup' element={<Signup/>}/>
          <Route path = '/Register' element={<Register/>}/>
        </Routes>
        <Routes>
          <Route path = '/courses' element={<CourseManager/>}/>
          <Route path = '/ManageClasses' element={<ManageClasses/>}/>
        </Routes>
      </div> 
  </Router>
  );
}

export default App;
