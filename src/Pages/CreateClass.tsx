import React, { useState } from 'react';
import { Route, Routes, Navigate, BrowserRouter as Router } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import '../Styles/CreateClass.css';

const ClassCreationPage: React.FC = () => {
  const navigate = useNavigate();
  const [classDetails, setClassDetails] = useState({
    className: '',
    instructors: [''],
    lectureTimes: [''],
    homeworkDueDates: [''],
    examDueDates: [''],
  });

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>, field: string) => {
    setClassDetails({
      ...classDetails,
      [field]: e.target.value,
    });
  };

  const handleAddInstructor = (e: React.FormEvent) => {
    e.preventDefault(); // Prevent the default form submission behavior.
    setClassDetails({
      ...classDetails,
      instructors: [...classDetails.instructors, ''],
    });
  };

  const handleInstructorChange = (e: React.ChangeEvent<HTMLInputElement>, index: number) => {
    const updatedInstructors = [...classDetails.instructors];
    updatedInstructors[index] = e.target.value;
    setClassDetails({
      ...classDetails,
      instructors: updatedInstructors,
    });
  };

  const handleAddLectureTime = (e: React.FormEvent) => {
    e.preventDefault(); // Prevent the default form submission behavior.
    setClassDetails({
      ...classDetails,
      lectureTimes: [...classDetails.lectureTimes, ''],
    });
  };

  const handleLectureTimeChange = (e: React.ChangeEvent<HTMLInputElement>, index: number) => {
    const updatedLectureTimes = [...classDetails.lectureTimes];
    updatedLectureTimes[index] = e.target.value;
    setClassDetails({
      ...classDetails,
      lectureTimes: updatedLectureTimes,
    });
  };

  const handleAddDueDate = (field: 'homeworkDueDates' | 'examDueDates', e: React.FormEvent) => {
    e.preventDefault(); // Prevent the default form submission behavior.
    setClassDetails({
      ...classDetails,
      [field]: [...classDetails[field], ''],
    });
  };

  const handleDueDateChange = (e: React.ChangeEvent<HTMLInputElement>, index: number, field: 'homeworkDueDates' | 'examDueDates') => {
    const updatedDueDates = [...classDetails[field]];
    updatedDueDates[index] = e.target.value;
    setClassDetails({
      ...classDetails,
      [field]: updatedDueDates,
    });
  };

  const handleCreateClass = (e: React.FormEvent) => {
    e.preventDefault(); // Prevent the default form submission behavior.
    setClassDetails({
        ...classDetails,
        instructors: classDetails.instructors.filter((instructor) => instructor.trim() !== ''),
        lectureTimes: classDetails.lectureTimes.filter((time) => time.trim() !== ''),
        homeworkDueDates: classDetails.homeworkDueDates.filter((date) => date.trim() !== ''),
        examDueDates: classDetails.examDueDates.filter((date) => date.trim() !== ''),
      });
    navigate('/');
  };

  return (
    <div className="CreateClassContainer">
      <h2>Create a College Class</h2>
      <form onSubmit={handleCreateClass}>
        <div>
          <label>Class Name:</label>
          <input
            type="text"
            value={classDetails.className}
            onChange={(e) => handleInputChange(e, 'className')}
          />
        </div>

        <div>
          <label>Instructors:</label>
          {classDetails.instructors.map((instructor, index) => (
            <div key={index}>
              <input
                type="text"
                value={instructor}
                onChange={(e) => handleInstructorChange(e, index)}
                placeholder="First name, Last name"
              />
            </div>
          ))}
          <button onClick={handleAddInstructor}>Add Instructor </button>
        </div>

        <div>
          <label>Lecture Times:</label>
          {classDetails.lectureTimes.map((time, index) => (
            <div key={index}>
              <input
                type="text"
                value={time}
                onChange={(e) => handleLectureTimeChange(e, index)}
                placeholder="Day, HH:mm-HH:mm"
              />
            </div>
          ))}
          <button onClick={handleAddLectureTime}>Add Lecture Time</button>
        </div>

        <div>
          <label>Homework Due Dates:</label>
          {classDetails.homeworkDueDates.map((date, index) => (
            <div key={index}>
              <input
                type="text"
                value={date}
                onChange={(e) => handleDueDateChange(e, index, 'homeworkDueDates')}
                placeholder="MM/DD"
              />
            </div>
          ))}
          <button onClick={(e) => handleAddDueDate('homeworkDueDates', e)}>Add Homework Due Date</button>
        </div>

        <div>
          <label>Exam Dates:</label>
          {classDetails.examDueDates.map((date, index) => (
            <div key={index}>
              <input
                type="text"
                value={date}
                onChange={(e) => handleDueDateChange(e, index, 'examDueDates')}
                placeholder="MM/DD"
              />
            </div>
          ))}
          <button onClick={(e) => handleAddDueDate('examDueDates', e)}>Add Exam Date</button>
        </div>

        <button type="submit">Create Class</button>
      </form>
    </div>
  );
};

export default ClassCreationPage;
