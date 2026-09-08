import React from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { mockAccounts, mockUser } from '../data/mockData';

export const Home: React.FC = () => {
  const navigate = useNavigate();
  const primaryAccount = mockAccounts[0];

  return (
    <div className="flex flex-col h-full bg-[var(--color-bg)] pb-16">
      {/* Header */}
      <div className="pt-10 pb-6 px-4 text-white" style={{ backgroundColor: 'var(--color-primary)' }}>
        <div className="flex justify-between items-center mb-6">
          <div>
            <p className="text-sm opacity-90">Welcome,</p>
            <h1 className="text-xl font-bold">{mockUser.name}</h1>
            <p className="text-xs opacity-75 mt-1">Last login: {mockUser.lastLogin}</p>
          </div>
          <div className="w-10 h-10 rounded-full bg-white/20 flex items-center justify-center">
            <span className="text-xl">🔔</span>
          </div>
        </div>

        {/* Balance Card */}
        <div className="bg-white rounded-[var(--radius-card)] p-4 text-[var(--color-text-primary)] shadow-md cursor-pointer" onClick={() => navigate('/accounts')}>
          <div className="flex justify-between items-center mb-2">
            <p className="text-sm font-medium">{primaryAccount.type}</p>
            <p className="text-xs text-[var(--color-text-secondary)]">{primaryAccount.accountNumber}</p>
          </div>
          <div className="flex items-end space-x-2">
            <span className="text-2xl font-bold">{primaryAccount.currency} {primaryAccount.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span>
          </div>
          <div className="mt-4 flex space-x-4 border-t border-[var(--color-divider)] pt-3">
            <button className="flex-1 text-sm font-medium text-[var(--color-primary)]">Mini Statement</button>
            <div className="w-px bg-[var(--color-divider)]"></div>
            <button className="flex-1 text-sm font-medium text-[var(--color-primary)]">Details</button>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        {/* Quick Actions Grid */}
        <div>
          <h3 className="text-sm font-bold text-[var(--color-text-secondary)] mb-3">QUICK ACTIONS</h3>
          <div className="grid grid-cols-4 gap-4">
            <div className="flex flex-col items-center" onClick={() => navigate('/transfer')}>
              <div className="w-12 h-12 rounded-full flex items-center justify-center mb-2 text-white" style={{ backgroundColor: 'var(--color-secondary)' }}>
                <span>💸</span>
              </div>
              <span className="text-xs text-center">Transfer</span>
            </div>
            <div className="flex flex-col items-center" onClick={() => navigate('/services')}>
              <div className="w-12 h-12 rounded-full flex items-center justify-center mb-2 text-white" style={{ backgroundColor: 'var(--color-secondary)' }}>
                <span>⚙️</span>
              </div>
              <span className="text-xs text-center">Services</span>
            </div>
            <div className="flex flex-col items-center" onClick={() => navigate('/home')}>
              <div className="w-12 h-12 rounded-full flex items-center justify-center mb-2 text-white" style={{ backgroundColor: 'var(--color-secondary)' }}>
                <span>📷</span>
              </div>
              <span className="text-xs text-center">Scan</span>
            </div>
            <div className="flex flex-col items-center" onClick={() => navigate('/home')}>
              <div className="w-12 h-12 rounded-full flex items-center justify-center mb-2 text-white" style={{ backgroundColor: 'var(--color-secondary)' }}>
                <span>💳</span>
              </div>
              <span className="text-xs text-center">Cards</span>
            </div>
          </div>
        </div>

        {/* Service Strip */}
        <div>
          <h3 className="text-sm font-bold text-[var(--color-text-secondary)] mb-3">EXPLORE BOB WORLD</h3>
          <div className="bg-white rounded-[var(--radius-card)] p-4 shadow-sm flex items-center justify-between">
            <div>
              <h4 className="font-bold text-[var(--color-primary)] mb-1">Over 240+ Services</h4>
              <p className="text-xs text-[var(--color-text-secondary)]">Experience banking like never before</p>
            </div>
            <button className="px-4 py-2 bg-[var(--color-accent)] text-white text-sm font-medium rounded-full" onClick={() => navigate('/services')}>
              Explore
            </button>
          </div>
        </div>
      </div>

      {/* Bottom Nav */}
      <div className="fixed bottom-0 left-0 right-0 bg-white border-t border-[var(--color-divider)] flex justify-around items-center h-16 pb-safe">
        <Link to="/home" className="flex flex-col items-center text-[var(--color-primary)]">
          <span className="text-xl mb-1">🏠</span>
          <span className="text-[10px] font-medium">Home</span>
        </Link>
        <Link to="/transfer" className="flex flex-col items-center text-[var(--color-text-secondary)]">
          <span className="text-xl mb-1">🔄</span>
          <span className="text-[10px] font-medium">Transfer</span>
        </Link>
        <Link to="/home" className="flex flex-col items-center text-[var(--color-text-secondary)]">
          <span className="text-xl mb-1">🛍️</span>
          <span className="text-[10px] font-medium">Shop</span>
        </Link>
        <Link to="/services" className="flex flex-col items-center text-[var(--color-text-secondary)]">
          <span className="text-xl mb-1">☰</span>
          <span className="text-[10px] font-medium">More</span>
        </Link>
      </div>
    </div>
  );
};
