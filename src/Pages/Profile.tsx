import React from 'react';
import { useNavigate } from 'react-router-dom';
import '../Styles/CreateClass.css';
import Login2 from "../Pages/Login2";

const UserProfile: React.FC = () => {
  const navigate = useNavigate();
  if(globalThis.userName === null || globalThis.userName === undefined) {return (<Login2/>);}
  return (
    <div className="CreateClassContainer">
      <h1>User Profile</h1>
      <div>
        <button
         onClick={()=>navigate('/ManageClasses')}>Manage classes
        </button>
      </div>
      <div>
        <button
          onClick={()=>navigate('/ChangePassword')}>Change password
        </button>
      </div>
      <div>
        <button
          onClick={()=>navigate('/DeleteProfile')}>Delete profile
        </button>
      </div>
    </div>
  );
};

export default UserProfile;