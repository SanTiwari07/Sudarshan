import React from 'react';
import { useNavigate } from 'react-router-dom';
import { USER_DATA } from '../data/mockData';

const Profile: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 pb-20">
      <div className="p-4 bg-white shadow-sm flex items-center gap-4">
        <button onClick={() => navigate(-1)} className="p-2 -ml-2">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <h1 className="text-lg font-bold">Profile & Settings</h1>
      </div>

      <div className="p-6 bg-white shadow-sm flex flex-col items-center mb-4">
        <div className="w-20 h-20 rounded-full flex items-center justify-center text-3xl font-bold mb-4" style={{ backgroundColor: 'var(--color-secondary)', color: 'white' }}>
          {USER_DATA.name.charAt(0)}
        </div>
        <h2 className="text-xl font-bold">{USER_DATA.name}</h2>
        <p className="text-gray-500 text-sm">CRN: {USER_DATA.crn}</p>
        <p className="text-xs text-gray-400 mt-2">Last Login: {USER_DATA.lastLogin}</p>
      </div>

      <div className="px-4 space-y-6">
        <div>
          <h3 className="text-xs font-bold text-gray-500 mb-3 uppercase">Account Settings</h3>
          <div className="bg-white rounded-xl shadow-sm overflow-hidden">
            <button className="w-full p-4 flex items-center justify-between border-b border-gray-100">
              <span className="font-medium">Personal Details</span>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-400"><path d="M9 18l6-6-6-6"/></svg>
            </button>
            <button className="w-full p-4 flex items-center justify-between border-b border-gray-100">
              <span className="font-medium">Change MPIN</span>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-400"><path d="M9 18l6-6-6-6"/></svg>
            </button>
            <button className="w-full p-4 flex items-center justify-between border-b border-gray-100">
              <span className="font-medium">Manage Fingerprint / Face ID</span>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-400"><path d="M9 18l6-6-6-6"/></svg>
            </button>
            <button onClick={() => navigate('/services')} className="w-full p-4 flex items-center justify-between">
              <span className="font-medium">Services</span>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-400"><path d="M9 18l6-6-6-6"/></svg>
            </button>
          </div>
        </div>

        <div>
          <h3 className="text-xs font-bold text-gray-500 mb-3 uppercase">Support</h3>
          <div className="bg-white rounded-xl shadow-sm overflow-hidden">
            <button className="w-full p-4 flex items-center justify-between border-b border-gray-100">
              <span className="font-medium">Help Center</span>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-400"><path d="M9 18l6-6-6-6"/></svg>
            </button>
            <button className="w-full p-4 flex items-center justify-between">
              <span className="font-medium">Contact Us</span>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-400"><path d="M9 18l6-6-6-6"/></svg>
            </button>
          </div>
        </div>

        <button
          onClick={() => navigate('/login')}
          className="w-full py-4 rounded-xl font-bold bg-white text-red-600 shadow-sm border border-red-100"
        >
          Logout
        </button>
      </div>
    </div>
  );
};

export default Profile;
