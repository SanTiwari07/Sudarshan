import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Search, Plus } from 'lucide-react';
import { mockPayees } from '../data/mockData';
import './Transfer.css';

export default function Transfer() {
  const navigate = useNavigate();

  return (
    <div className="transfer-screen page-container">
      <header className="page-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={24} />
        </button>
        <h1>Transfer Money</h1>
      </header>

      <div className="page-content">
        <div className="search-bar">
          <Search size={20} className="search-icon" />
          <input type="text" placeholder="Search payee or enter UPI ID" />
        </div>

        <div className="quick-transfer-actions">
          <button className="add-payee-btn">
            <div className="icon-circle"><Plus size={24} /></div>
            <span>New Payee</span>
          </button>
        </div>

        <section className="payee-list-section">
          <h2>Recent Payees</h2>
          <div className="payee-list">
            {mockPayees.map(payee => (
              <div key={payee.id} className="payee-item" onClick={() => navigate('/transfer/amount', { state: { payee } })}>
                <div className="payee-avatar">{payee.initials}</div>
                <div className="payee-info">
                  <p className="payee-name">{payee.name}</p>
                  <p className="payee-detail">{payee.vpa || payee.account}</p>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
