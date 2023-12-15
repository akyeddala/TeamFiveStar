//not used
import React, { useState, useEffect } from 'react';
import {Route, Routes, Navigate, BrowserRouter as Router} from 'react-router-dom';
import {MDBBtn, MDBContainer, MDBRow, MDBCol, MDBCard, MDBCardBody, MDBInput, MDBSwitch} from 'mdb-react-ui-kit';
import '../Styles/Login.css'


function Signup() {
    
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [cPassword, setCPassword] = useState("");
    const [isTeacher, setRole] = useState("I am a Student");
    
    const roleSwitch = () => {
        if (isTeacher === "I am a Teacher")
            setRole("I am a Student");
        else
            setRole("I am a Teacher");
    }

    return(
        <MDBContainer fluid>

            <MDBRow className='d-flex justify-content-center align-items-center h-100'>
                <MDBCol col='12'>

                <MDBCard className='bg-dark text-white my-5 mx-auto' style={{borderRadius: '1rem', maxWidth: '400px'}}>
                    <MDBCardBody className='p-5 d-flex flex-column align-items-center mx-auto w-100'>

                    <h2 className="mb-2 text-uppercase">Sign Up</h2>
                    <p className="text-white-50 mb-5">Please enter your information!</p>
                    <MDBInput wrapperClass='mb-4 mx-5 w-100' labelClass='text-white' label='Email address' id='formControlLg' type='email' size="lg" value={email} onChange={(e) => setEmail(e.target.value)}/>
                    <MDBInput wrapperClass='mb-4 mx-5 w-100' labelClass='text-white' label='Password' id='formControlLg' type='password' size="lg" value={password} onChange={(e) => setPassword(e.target.value)}/>
                    <MDBInput wrapperClass='mb-4 mx-5 w-100' labelClass='text-white' label='Confirm Password' id='formControlLg' type='password' size="lg" value={cPassword} onChange={(e) => setCPassword(e.target.value)}/>

                    <MDBSwitch id='roleSwitch' onChange = {e => roleSwitch()} label = {isTeacher}/>

                    <MDBBtn outline className='mx-2 px-5' size='lg'>
                        Sign Up
                    </MDBBtn>

                    <div>
                        <p className="mb-0">Have an account? <a href="#Login" className="text-blue-50 fw-bold">Log In</a></p> {/*changed class to className */}
                    </div>  

                    </MDBCardBody>
                </MDBCard>

                </MDBCol>
            </MDBRow>

            </MDBContainer>
    );
}

export default Signup;