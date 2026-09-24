import React from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Bell, 
  Wallet, 
  ArrowRightLeft, 
  CreditCard, 
  FileText, 
  Building2,
  ChevronRight,
  Eye,
  EyeOff
} from 'lucide-react';
import { mockData } from '../mock/data';
import './Home.css';

export const Home: React.FC = () => {
  const navigate = useNavigate();
  const [showBalance, setShowBalance] = React.useState(false);
  const primaryAccount = mockData.accounts[0];

  const quickActions = [
    { icon: ArrowRightLeft, label: 'Transfer', route: '/transfer' },
    { icon: Wallet, label: 'Pay Bills', route: '/services' },
    { icon: CreditCard, label: 'Cards', route: '/services' },
    { icon: FileText, label: 'Statements', route: '/accounts' },
  ];

  return (
    <div className="home-screen">
      <div className="home-header">
        <div className="header-top">
          <div className="user-greeting">
            <div className="avatar-small">
              <span>{mockData.user.name.charAt(0)}</span>
            </div>
            <div>
              <p>Welcome back,</p>
              <h2>{mockData.user.name}</h2>
            </div>
          </div>
          <button className="icon-button">
            <Bell size={24} />
          </button>
        </div>
        <p className="last-login">Last login: {mockData.user.lastLogin}</p>
      </div>

      <div className="home-content">
        <div className="account-summary-card">
          <div className="card-header">
            <div>
              <h3>{primaryAccount.type}</h3>
              <p>{primaryAccount.accountNumber}</p>
            </div>
            <Building2 size={24} className="bank-icon" />
          </div>
          <div className="balance-section">
            <p>Available Balance</p>
            <div className="balance-display">
              <h2>{showBalance ? `₹${primaryAccount.balance.toLocaleString('en-IN')}` : '₹ •••••••'}</h2>
              <button onClick={() => setShowBalance(!showBalance)} className="toggle-balance">
                {showBalance ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>
          </div>
          <button className="view-details-btn" onClick={() => navigate('/accounts')}>
            View Details <ChevronRight size={16} />
          </button>
        </div>

        <div className="quick-actions-section">
          <h3>Quick Actions</h3>
          <div className="actions-grid">
            {quickActions.map((action, index) => (
              <button 
                key={index} 
                className="action-item"
                onClick={() => navigate(action.route)}
              >
                <div className="action-icon">
                  <action.icon size={24} />
                </div>
                <span>{action.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="recent-activity-section">
          <div className="section-header">
            <h3>Recent Activity</h3>
            <button className="text-btn" onClick={() => navigate('/accounts')}>View All</button>
          </div>
          <div className="activity-list">
            {mockData.transactions.slice(0, 3).map((txn) => (
              <div key={txn.id} className="activity-item">
                <div className="activity-details">
                  <div className={`activity-icon ${txn.type}`}>
                    <ArrowRightLeft size={16} />
                  </div>
                  <div>
                    <h4>{txn.description}</h4>
                    <p>{txn.date}</p>
                  </div>
                </div>
                <div className={`activity-amount ${txn.type}`}>
                  {txn.type === 'credit' ? '+' : '-'}₹{Math.abs(txn.amount).toLocaleString('en-IN')}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
