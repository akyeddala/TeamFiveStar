import React, { useState, useEffect } from 'react';
import {Route, Routes, Navigate, BrowserRouter as Router} from 'react-router-dom';
import { styled } from '@mui/material/styles';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell, { tableCellClasses } from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import '../Styles/CourseManager.css';

function CourseManager() {

    const [staff, setStaff] = useState(new Map<String, String>()); //name, role
    const [events, setEvents] = useState(new Map<String, String>()); //event, date (maybe switch to date object)
    const [lectures, setLectures] = useState(new Map<String, String>()); //event, date/time (maybe switch to date object)

    const StyledTableCell = styled(TableCell)(({ theme }) => ({
        [`&.${tableCellClasses.head}`]: {
          backgroundColor: theme.palette.error.dark,
          color: theme.palette.common.white,
        },
        [`&.${tableCellClasses.body}`]: {
          fontSize: 14,
        },
      }));


    return (
        <div className='d-flex vh-100 justify-content-center align-items-center'>
            

            <TableContainer component={Paper} sx={{elevation: 3, margin: '1%'}}>
                <Table sx={{ align: 'left', width: '100%' }} aria-label="simple table">
                    <TableHead>
                        <TableRow > 
                            <StyledTableCell colSpan={2} align= 'center'>
                                Staff
                            </StyledTableCell>
                        </TableRow>
                        <TableRow>
                            <TableCell align= 'center'>Name</TableCell>
                            <TableCell align= 'center'>Role</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>

                    </TableBody>
                </Table>
            </TableContainer>

            <TableContainer component={Paper} sx={{elevation: 3, margin: '1%'}}>
                <Table sx={{ width: '100%' }} aria-label="simple table">
                    <TableHead>
                    <TableRow > 
                            <StyledTableCell colSpan={2} align= 'center'>
                                Events
                            </StyledTableCell>
                        </TableRow>
                        <TableRow>
                            <TableCell align= 'center'>Event</TableCell>
                            <TableCell align= 'center'>Date</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        
                    </TableBody>
                </Table>
            </TableContainer>

            <TableContainer component={Paper} sx={{elevation: 3, margin: '1%'}}>
            <Table sx={{ width: '100%' }} aria-label="simple table">
                    <TableHead>
                        <TableRow > 
                            <StyledTableCell colSpan={2} align= 'center'>
                                Lectures
                            </StyledTableCell>
                        </TableRow>
                        <TableRow>
                            <TableCell align= 'center'>Event</TableCell>
                            <TableCell align= 'center'>Date</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        
                    </TableBody>
                </Table>
                
            </TableContainer>
        </div>
    );
}

export default CourseManager;