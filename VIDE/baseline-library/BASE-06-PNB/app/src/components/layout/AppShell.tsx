import React from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { Home, Wallet, CreditCard, Menu } from 'lucide-react';
import './AppShell.css';

export const AppShell: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();

  // Simple bottom nav definition
  const navItems = [
    { path: '/home', icon: Home, label: 'Home' },
    { path: '/accounts', icon: Wallet, label: 'Accounts' },
    { path: '/transfer', icon: CreditCard, label: 'Pay' },
    { path: '/more', icon: Menu, label: 'More' },
  ];

  const hideNavPaths = ['/', '/login', '/mpin', '/splash'];
  const showNav = !hideNavPaths.includes(location.pathname);

  return (
    <div className="app-shell">
      <div className="app-content">
        <Outlet />
      </div>
      {showNav && (
        <nav className="bottom-nav">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname.startsWith(item.path);
            return (
              <button
                key={item.path}
                className={`nav-item ${isActive ? 'active' : ''}`}
                onClick={() => navigate(item.path)}
              >
                <Icon size={24} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      )}
    </div>
  );
};
