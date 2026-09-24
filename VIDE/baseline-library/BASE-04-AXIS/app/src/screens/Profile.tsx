import { useNavigate } from 'react-router-dom';
import { ArrowLeft, User, Settings, Shield, Bell, HelpCircle, LogOut, ChevronRight } from 'lucide-react';
import { mockUser } from '../data/mockData';
import { Button } from '../components/primitives/Button';
import './Profile.css';

export default function Profile() {
  const navigate = useNavigate();

  const handleLogout = () => {
    navigate('/login');
  };

  const menuGroups = [
    {
      items: [
        { icon: User, label: 'Personal Details' },
        { icon: Shield, label: 'Security & MPIN' },
      ]
    },
    {
      items: [
        { icon: Settings, label: 'App Settings' },
        { icon: Bell, label: 'Notifications' },
      ]
    },
    {
      items: [
        { icon: HelpCircle, label: 'Help & Support' },
      ]
    }
  ];

  return (
    <div className="profile-screen page-container">
      <header className="page-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={24} />
        </button>
        <h1>Profile</h1>
      </header>

      <div className="page-content">
        <div className="profile-header-card">
          <div className="profile-avatar-large">{mockUser.name.charAt(0)}</div>
          <div className="profile-user-info">
            <h2>{mockUser.name}</h2>
            <p>Customer ID: 88****432</p>
            <span className="last-login-badge">Last login: {mockUser.lastLogin}</span>
          </div>
        </div>

        <div className="profile-menu">
          {menuGroups.map((group, groupIdx) => (
            <div key={groupIdx} className="menu-group">
              {group.items.map((item, itemIdx) => {
                const Icon = item.icon;
                return (
                  <div key={itemIdx} className="menu-item" onClick={() => {}}>
                    <div className="menu-icon-wrapper">
                      <Icon size={20} className="menu-icon" />
                    </div>
                    <span className="menu-label">{item.label}</span>
                    <ChevronRight size={20} className="menu-chevron" />
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        <div className="logout-container">
          <Button variant="secondary" fullWidth onClick={handleLogout} className="logout-btn">
            <LogOut size={20} style={{ marginRight: '8px' }} />
            Logout
          </Button>
          <p className="app-version">Axis Mobile v10.2.1</p>
        </div>
      </div>
    </div>
  );
}
