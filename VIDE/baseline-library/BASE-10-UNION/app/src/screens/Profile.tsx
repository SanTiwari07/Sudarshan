
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { User, Mail, Phone, MapPin, LogOut } from 'lucide-react';
import './Profile.css';

export function Profile() {
  const navigate = useNavigate();

  return (
    <div className="union-profile" data-testid="UNION-PROFILE">
      <Header title="My Profile" showBack />
      
      <div className="profile-content">
        <div className="profile-header">
          <div className="profile-avatar">
            <User size={48} color="var(--color-surface)" />
          </div>
          <h2>Rahul Sharma</h2>
          <p>Customer ID: 987654321</p>
        </div>

        <div className="profile-details">
          <div className="profile-row">
            <div className="profile-icon"><Phone size={20} /></div>
            <div className="profile-info">
              <span>Mobile Number</span>
              <strong>+91 98765 43210</strong>
            </div>
          </div>
          <div className="profile-row">
            <div className="profile-icon"><Mail size={20} /></div>
            <div className="profile-info">
              <span>Email Address</span>
              <strong>rahul.sharma@example.com</strong>
            </div>
          </div>
          <div className="profile-row">
            <div className="profile-icon"><MapPin size={20} /></div>
            <div className="profile-info">
              <span>Communication Address</span>
              <strong>123, Marine Drive, Mumbai, 400020</strong>
            </div>
          </div>
        </div>

        <button className="logout-btn" onClick={() => navigate('/login')}>
          <LogOut size={20} />
          <span>Logout</span>
        </button>
      </div>
    </div>
  );
}
