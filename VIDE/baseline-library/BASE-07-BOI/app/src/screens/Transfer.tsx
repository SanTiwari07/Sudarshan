import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, Search, User } from 'lucide-react';
import { mockData } from '../mock/data';
import './Transfer.css';

export const Transfer: React.FC = () => {
  const navigate = useNavigate();

  const handlePayeeSelect = (payeeId: string) => {
    navigate('/transfer/amount', { state: { payeeId } });
  };

  return (
    <div className="transfer-screen">
      <header className="screen-header">
        <button className="back-btn" onClick={() => navigate('/home')}>
          <ChevronLeft size={24} />
        </button>
        <h1>Fund Transfer</h1>
        <div style={{ width: 24 }}></div>
      </header>

      <div className="transfer-content">
        <div className="search-bar">
          <Search size={20} className="search-icon" />
          <input type="text" placeholder="Search Payee or VPA" />
        </div>

        <div className="recent-payees-section">
          <h3>Recent Payees</h3>
          <div className="payees-list">
            {mockData.payees.map((payee) => (
              <button 
                key={payee.id} 
                className="payee-item"
                onClick={() => handlePayeeSelect(payee.id)}
              >
                <div className="payee-avatar">
                  <User size={20} />
                </div>
                <div className="payee-info">
                  <h4>{payee.name}</h4>
                  <p>{payee.bank} • {payee.account}</p>
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="new-transfer-options">
          <h3>Transfer Money</h3>
          <button className="transfer-option-btn">
            To Bank Account
          </button>
          <button className="transfer-option-btn">
            To Mobile Number
          </button>
          <button className="transfer-option-btn">
            To UPI ID
          </button>
        </div>
      </div>
    </div>
  );
};
