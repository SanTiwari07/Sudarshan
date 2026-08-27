import { useNavigate } from 'react-router-dom';
import { ArrowLeft, CreditCard, Shield, FileText, Smartphone } from 'lucide-react';
import './Services.css';

export default function Services() {
  const navigate = useNavigate();

  const serviceCategories = [
    {
      title: 'Cards',
      items: [
        { icon: CreditCard, label: 'Credit Cards', desc: 'Apply, manage or block' },
        { icon: CreditCard, label: 'Debit Cards', desc: 'Manage limits and PIN' }
      ]
    },
    {
      title: 'Investments',
      items: [
        { icon: FileText, label: 'Fixed Deposits', desc: 'Open new FD' },
        { icon: FileText, label: 'Mutual Funds', desc: 'Invest in MFs' }
      ]
    },
    {
      title: 'Loans & Offers',
      items: [
        { icon: Shield, label: 'Personal Loan', desc: 'Pre-approved offers' },
        { icon: Smartphone, label: 'Recharge & Pay', desc: 'Mobile, DTH, Utility' }
      ]
    }
  ];

  return (
    <div className="services-screen page-container">
      <header className="page-header">
        <button className="back-button" onClick={() => navigate(-1)}>
          <ArrowLeft size={24} />
        </button>
        <h1>Services</h1>
      </header>

      <div className="page-content">
        {serviceCategories.map((category, idx) => (
          <div key={idx} className="service-category">
            <h2 className="category-title">{category.title}</h2>
            <div className="service-grid">
              {category.items.map((item, itemIdx) => {
                const Icon = item.icon;
                return (
                  <div key={itemIdx} className="service-card" onClick={() => {}}>
                    <div className="service-icon-bg">
                      <Icon size={24} className="service-icon" />
                    </div>
                    <div className="service-info">
                      <h3>{item.label}</h3>
                      <p>{item.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
