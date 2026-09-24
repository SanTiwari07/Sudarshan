
import { useNavigate } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { User, Plus } from 'lucide-react';
import './Transfer.css';

export function Transfer() {
  const navigate = useNavigate();

  const payees = [
    { id: '1', name: 'Rohan Sharma', bank: 'HDFC Bank', acc: 'XXXX 4321' },
    { id: '2', name: 'Aarti Singh', bank: 'ICICI Bank', acc: 'XXXX 8765' }
  ];

  const handleSelectPayee = (payee: any) => {
    navigate('/transfer/amount', { state: { payee } });
  };

  return (
    <div className="union-transfer" data-testid="UNION-TRANSFER">
      <Header title="Fund Transfer" showBack />
      
      <div className="transfer-content">
        <button className="add-payee-btn">
          <div className="add-icon"><Plus size={24} /></div>
          <div className="add-text">
            <h4>Add New Payee</h4>
            <span>Transfer to new bank account</span>
          </div>
        </button>

        <h3 className="section-title">Recent Payees</h3>
        
        <div className="payees-list">
          {payees.map(payee => (
            <div key={payee.id} className="payee-item" onClick={() => handleSelectPayee(payee)}>
              <div className="payee-avatar">
                <User size={24} color="var(--color-surface)" />
              </div>
              <div className="payee-info">
                <h4>{payee.name}</h4>
                <span>{payee.bank} • {payee.acc}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
