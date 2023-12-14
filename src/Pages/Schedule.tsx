import React, { useState, useEffect } from 'react';
import Calendar from 'react-calendar';
import '../Styles/Table.css';
import '../Styles/MainPage.css';
import 'react-calendar/dist/Calendar.css';
import { Routes, Route, useParams } from 'react-router-dom';
import {fetch2, fetch3} from '../endpointFunction';

const check = async (): Promise<void> => {
    if(globalThis.userName === null || globalThis.userName === undefined) {
        return [[]];
    }
    else {
        //const reLogin = await fetch2('/login','POST',{"email":globalThis.userName,"password":globalThis.password});
        const response = await fetch3('/users/schedule/', 'GET');
        const ret = await response.json().then(ret => {return ret["schedule"];});
        return ret;
    }
}
const Schedule = () => {
    const [date, setDate] = useState(new Date());
    const [multi, setMulti] = useState([
    [0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0,0,0]
    ]);
    useEffect( () => {
        async function fetchData() {
        try {
            const res = await check();
            setMulti(res);
        } catch (err) {
          console.log(err);
        }
    }
                fetchData();
            }, []);
    const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
    const times = Array.from({ length: 13 }, (_, index) => index + 7);
    return (
      <table className="time-table">
          <thead>
            <tr>
              <th></th>
              {days.map((day, index) => (
                <th key={index}>{day}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {times.map((time, index) => (
              <tr key={index}>
                <td>{`${time}:00`}</td>
                {days.map((day, dayIndex) => (
                  <td
                    key={dayIndex}
                    className={multi.length !== 0 ? multi[dayIndex][index] === 1 ? 'colored-cell' : '' : ""}
                   ></td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
    );
  }
  export default Schedule