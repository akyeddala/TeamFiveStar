import React, { useState, useEffect } from 'react';
import {Route, Routes, Navigate, BrowserRouter as Router} from 'react-router-dom';
import Calendar from 'react-calendar';
import Schedule from "./Schedule";
import Login2 from "../Pages/Login2";
import '../Styles/Table.css';
import '../Styles/MainPage.css';
import 'react-calendar/dist/Calendar.css';

function MainPage() {
    if(globalThis.userName === null || globalThis.userName === undefined) {return (<Login2/>);}
    return (
      <div className ='app'>
        <h2 className ='text-center'>Office Hours Calendar</h2>
        <div className ='calendar-container'>
          <Schedule/>
        </div>
      </div>
    );
  }

  export default MainPage;