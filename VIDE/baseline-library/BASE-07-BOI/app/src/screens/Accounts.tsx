import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, Building2, Download, Filter } from 'lucide-react';
import { mockData } from '../mock/data';
import './Accounts.css';

export const Accounts: React.FC = () => {
  const navigate = useNavigate();
  const account = mockData.accounts[0];

  return (
    <div className="accounts-screen">
      <header className="screen-header">
        <button className="back-btn" onClick={() => navigate('/home')}>
          <ChevronLeft size={24} />
        </button>
        <h1>Account Details</h1>
        <div style={{ width: 24 }}></div> {/* spacer */}
      </header>

      <div className="account-detail-card">
        <div className="card-top">
          <div className="acc-info">
            <p>Account Number</p>
            <h3>{account.accountNumber}</h3>
            <span className="acc-type-badge">{account.type}</span>
          </div>
          <Building2 size={32} className="bank-icon-large" />
        </div>
        
        <div className="acc-balance">
          <p>Available Balance</p>
          <h2>₹{account.balance.toLocaleString('en-IN')}</h2>
        </div>

        <div className="acc-actions">
          <button className="acc-action-btn">
            <Download size={20} />
            <span>Statement</span>
          </button>
        </div>
      </div>

      <div className="transactions-section">
        <div className="section-header">
          <h3>Recent Transactions</h3>
          <button className="icon-btn">
            <Filter size={20} />
          </button>
        </div>

        <div className="txn-list">
          {mockData.transactions.map((txn) => (
            <div key={txn.id} className="txn-item">
              <div className="txn-left">
                <div className={`txn-dot ${txn.type}`}></div>
                <div>
                  <h4>{txn.description}</h4>
                  <p>{txn.date}</p>
                </div>
              </div>
              <div className={`txn-right ${txn.type}`}>
                {txn.type === 'credit' ? '+' : '-'}₹{Math.abs(txn.amount).toLocaleString('en-IN')}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
