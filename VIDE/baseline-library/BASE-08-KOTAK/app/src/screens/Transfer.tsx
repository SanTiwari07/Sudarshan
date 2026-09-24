import React from 'react';
import { useNavigate } from 'react-router-dom';
import { PAYEES } from '../data/mockData';

const Transfer: React.FC = () => {
  const navigate = useNavigate();

  const handleSelectPayee = (payeeId: string) => {
    navigate('/transfer/amount', { state: { payeeId } });
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-50 pb-20">
      <div className="p-4 bg-white shadow-sm flex items-center gap-4">
        <button onClick={() => navigate('/home')} className="p-2 -ml-2">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <h1 className="text-lg font-bold" style={{ color: 'var(--color-text-primary)' }}>Send Money</h1>
      </div>

      <div className="p-4">
        <div className="mb-6 relative">
          <input
            type="text"
            placeholder="Search by Name, UPI ID, or Mobile"
            className="w-full p-4 pl-12 bg-white border border-gray-200 rounded-xl"
          />
          <svg className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        </div>

        <h3 className="text-sm font-bold text-gray-500 mb-2">RECENT PAYEES</h3>
        
        <div className="bg-white rounded-xl shadow-sm overflow-hidden">
          {PAYEES.map((payee, idx) => (
            <div 
              key={payee.id}
              onClick={() => handleSelectPayee(payee.id)}
              className={`p-4 flex items-center gap-4 cursor-pointer active:bg-gray-50 ${idx !== PAYEES.length - 1 ? 'border-b border-gray-100' : ''}`}
            >
              <div className="w-12 h-12 rounded-full flex items-center justify-center text-lg font-bold shadow-sm" style={{ backgroundColor: 'var(--color-secondary)', color: 'white' }}>
                {payee.name.charAt(0)}
              </div>
              <div className="flex-1">
                <p className="font-bold text-gray-900">{payee.name}</p>
                <p className="text-sm text-gray-500">{payee.vpa}</p>
              </div>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-400"><path d="M9 18l6-6-6-6"/></svg>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Transfer;
