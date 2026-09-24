import React from 'react';
import { useNavigate } from 'react-router-dom';
import { USER_DATA, ACCOUNTS, TRANSACTIONS } from '../data/mockData';

const Home: React.FC = () => {
  const navigate = useNavigate();
  const primaryAccount = ACCOUNTS[0];

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 pb-24">
      {/* Header */}
      <div className="flex justify-between items-center p-5 bg-white shadow-sm sticky top-0 z-10">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-full flex items-center justify-center text-white" style={{ backgroundColor: 'var(--color-primary)' }}>
            <span className="font-bold text-lg">{USER_DATA.name.charAt(0)}</span>
          </div>
          <div className="flex flex-col">
            <p className="text-xs text-gray-500 font-medium">Welcome back,</p>
            <h2 className="text-base font-bold text-gray-900 tracking-tight">{USER_DATA.name}</h2>
          </div>
        </div>
        <div className="flex gap-2">
          <button onClick={() => navigate('/scan')} className="p-2.5 rounded-full bg-gray-50 text-gray-700 hover:bg-gray-100 transition-colors">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="10" height="10"></rect></svg>
          </button>
          <button onClick={() => navigate('/profile')} className="p-2.5 rounded-full bg-gray-50 text-gray-700 hover:bg-gray-100 transition-colors">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>
          </button>
        </div>
      </div>

      <div className="p-4 space-y-6">
        {/* Account Summary Card */}
        <div className="rounded-2xl p-6 shadow-lg relative overflow-hidden" style={{ backgroundColor: 'var(--color-secondary)', color: 'var(--color-surface)' }}>
          {/* Decorative circles */}
          <div className="absolute -top-12 -right-12 w-32 h-32 rounded-full opacity-10 bg-white"></div>
          <div className="absolute -bottom-8 -left-8 w-24 h-24 rounded-full opacity-10 bg-white"></div>
          
          <div className="flex justify-between items-start mb-6 relative z-10">
            <div className="flex flex-col">
              <span className="text-xs font-semibold tracking-wider uppercase opacity-80 mb-1">{primaryAccount.type}</span>
              <span className="text-sm font-mono opacity-90">{primaryAccount.number}</span>
            </div>
            <button onClick={() => navigate('/accounts')} className="text-xs font-medium py-1.5 px-4 rounded-full bg-white/10 hover:bg-white/20 transition-colors backdrop-blur-sm border border-white/20">
              View All
            </button>
          </div>
          <div className="mb-6 relative z-10">
            <p className="text-sm font-medium opacity-80 mb-1">Available Balance</p>
            <h1 className="text-4xl font-extrabold tracking-tight">₹ {primaryAccount.balance.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</h1>
          </div>
          <div className="flex justify-between border-t border-white/20 pt-5 relative z-10">
            <button onClick={() => navigate('/accounts/details')} className="text-sm font-semibold opacity-90 hover:opacity-100 transition-opacity">Statements</button>
            <button onClick={() => navigate('/transfer')} className="text-sm font-semibold flex items-center gap-1.5 opacity-90 hover:opacity-100 transition-opacity">
              Transfer Money <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </button>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="py-2">
          <h3 className="text-sm font-bold mb-4 tracking-wide" style={{ color: 'var(--color-text-secondary)' }}>QUICK ACTIONS</h3>
          <div className="grid grid-cols-4 gap-y-6 gap-x-2">
            <button onClick={() => navigate('/transfer')} className="flex flex-col items-center group">
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-2 shadow-sm bg-white border border-gray-100 group-hover:shadow-md transition-all">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2.5"><path d="M12 5v14M5 12h14"/></svg>
              </div>
              <span className="text-[11px] font-semibold text-center leading-tight text-gray-700">Transfer<br/>Money</span>
            </button>
            <button onClick={() => navigate('/scan')} className="flex flex-col items-center group">
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-2 shadow-sm bg-white border border-gray-100 group-hover:shadow-md transition-all">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2.5"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/></svg>
              </div>
              <span className="text-[11px] font-semibold text-center leading-tight text-gray-700">Scan<br/>Any QR</span>
            </button>
            <button onClick={() => navigate('/home')} className="flex flex-col items-center group">
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-2 shadow-sm bg-white border border-gray-100 group-hover:shadow-md transition-all">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2.5"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
              </div>
              <span className="text-[11px] font-semibold text-center leading-tight text-gray-700">Pay<br/>Bills</span>
            </button>
            <button onClick={() => navigate('/home')} className="flex flex-col items-center group">
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-2 shadow-sm bg-white border border-gray-100 group-hover:shadow-md transition-all">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2.5"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
              </div>
              <span className="text-[11px] font-semibold text-center leading-tight text-gray-700">Recharge<br/>Mobile</span>
            </button>
          </div>
        </div>

        {/* Offers Strip */}
        <div className="bg-gradient-to-r from-orange-100 to-red-100 rounded-xl p-4 flex justify-between items-center cursor-pointer">
          <div>
            <h4 className="font-bold text-sm" style={{ color: 'var(--color-accent)' }}>Get Kotak 811 Credit Card</h4>
            <p className="text-xs text-gray-600 mt-1">Lifetime Free + Rewards</p>
          </div>
          <button className="bg-white rounded-full p-2 text-xs font-bold px-4 shadow-sm" style={{ color: 'var(--color-primary)' }}>
            Apply Now
          </button>
        </div>

        {/* Recent Activity */}
        <div>
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-sm font-bold" style={{ color: 'var(--color-text-secondary)' }}>RECENT TRANSACTIONS</h3>
            <button onClick={() => navigate('/transactions')} className="text-xs font-medium" style={{ color: 'var(--color-primary)' }}>View All</button>
          </div>
          <div className="bg-white rounded-xl shadow-sm overflow-hidden">
            {TRANSACTIONS.slice(0, 3).map((tx, idx) => (
              <div key={tx.id} className={`p-4 flex justify-between items-center ${idx !== 2 ? 'border-b border-gray-100' : ''}`}>
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center bg-gray-50" style={{ color: 'var(--color-secondary)' }}>
                    <span className="text-sm font-bold">{tx.description.charAt(0)}</span>
                  </div>
                  <div>
                    <p className="font-medium text-sm text-gray-900">{tx.description}</p>
                    <p className="text-xs text-gray-500">{tx.date}</p>
                  </div>
                </div>
                <p className={`font-bold text-sm ${tx.type === 'credit' ? 'text-green-600' : 'text-gray-900'}`}>
                  {tx.type === 'credit' ? '+' : '-'}₹ {Math.abs(tx.amount).toFixed(2)}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;
