import React, { useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { Home, ArrowRightLeft, User, Bell } from 'lucide-react';
import { Toast } from '../primitives/Toast';
import { Modal } from '../primitives/Modal';
import './AppShell.css';

export const AppShell: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const navItems = [
    { path: '/home', icon: Home, label: 'Home' },
    { path: '/transfer', icon: ArrowRightLeft, label: 'Transfer' },
    { path: '/profile', icon: User, label: 'Profile' }
  ];

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <div className="app-header-left">
          <h2>IndusMobile</h2>
        </div>
        <div className="app-header-right">
          <button className="icon-button" onClick={() => setToastMessage("No new notifications")}>
            <Bell size={24} />
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="main-content">
        <Outlet />
      </main>

      {/* Bottom Navigation */}
      <nav className="bottom-nav">
        {navItems.map((item) => (
          <button
            key={item.path}
            className={`nav-item ${location.pathname.startsWith(item.path) ? 'active' : ''}`}
            onClick={() => navigate(item.path)}
          >
            <item.icon size={24} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>

      {/* Toast Layer */}
      {toastMessage && (
        <Toast 
          message={toastMessage} 
          onClose={() => setToastMessage(null)} 
        />
      )}

      {/* Modal Layer */}
      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title="System Info">
        <p>This is a system modal.</p>
      </Modal>
    </div>
  );
};
