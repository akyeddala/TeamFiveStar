import Container from 'react-bootstrap/Container';
import Nav from 'react-bootstrap/Nav';
import Navbar from 'react-bootstrap/Navbar';
//import '../Styles/NavBar.css';

function NavBar() {
    return (
        <Container>
            <Navbar fixed="top" bg = "dark" data-bs-theme = "dark">
                <Container>
                    <Navbar.Brand href ="./">Office Hours App</Navbar.Brand>
                    <Nav className = "me-auto">
                        <Nav.Link href = "./">Home</Nav.Link>
                        <Nav.Link href = "./login">Login</Nav.Link>
                        <Nav.Link href = "./JoinClass">Create/join class</Nav.Link>
                        <Nav.Link href = "./Profile">Profile</Nav.Link>
                    </Nav>
                </Container>
            </Navbar>
        </Container>    
    );
}

export default NavBar;