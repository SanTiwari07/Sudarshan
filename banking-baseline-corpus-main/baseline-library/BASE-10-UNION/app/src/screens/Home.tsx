
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { Send, CreditCard, LayoutGrid, QrCode } from 'lucide-react';
import './Home.css';

export function Home() {
  const navigate = useNavigate();

  return (
    <div className="union-home" data-testid="UNION-HOME">
      <Header title="Vyom" showNotifications />
      
      <div className="home-content">
        <div className="greeting-section">
          <h2>Good Morning, Rahul</h2>
          <p>Last login: 12 Aug 2026, 10:30 AM</p>
        </div>

        <div className="account-summary-card">
          <div className="account-header">
            <span>Savings Account</span>
            <span>XXXX 1234</span>
          </div>
          <div className="account-balance">
            <h3>₹ 45,230.00</h3>
            <button className="view-stmt-btn" onClick={() => navigate('/accounts/1/transactions')}>View Statement</button>
          </div>
        </div>

        <div className="quick-actions-grid">
          <button className="action-item" onClick={() => navigate('/transfer')}>
            <div className="icon-wrapper"><Send size={24} /></div>
            <span>Transfer</span>
          </button>
          <button className="action-item" onClick={() => navigate('/transfer')}>
            <div className="icon-wrapper"><CreditCard size={24} /></div>
            <span>Pay Cards</span>
          </button>
          <button className="action-item" onClick={() => navigate('/services')}>
            <div className="icon-wrapper"><LayoutGrid size={24} /></div>
            <span>Services</span>
          </button>
          <button className="action-item" onClick={() => navigate('/transfer')}>
            <div className="icon-wrapper"><QrCode size={24} /></div>
            <span>Scan & Pay</span>
          </button>
        </div>

        <div className="service-strip">
          <div className="service-strip-item">Pre-approved Loan</div>
          <div className="service-strip-item">FD / RD</div>
        </div>

        <div className="recent-activity">
          <h3>Recent Transactions</h3>
          <div className="activity-list">
            <div className="activity-item">
              <div className="activity-details">
                <span className="activity-title">Amazon</span>
                <span className="activity-date">11 Aug 2026</span>
              </div>
              <span className="activity-amount negative">- ₹ 1,200.00</span>
            </div>
            <div className="activity-item">
              <div className="activity-details">
                <span className="activity-title">Salary Credit</span>
                <span className="activity-date">01 Aug 2026</span>
              </div>
              <span className="activity-amount positive">+ ₹ 85,000.00</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
