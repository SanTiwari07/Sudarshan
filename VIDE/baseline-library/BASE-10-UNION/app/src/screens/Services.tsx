
import { Header } from '../components/layout/Header';
import { Settings, CreditCard, Shield, FileText, ChevronRight } from 'lucide-react';
import './Services.css';

export function Services() {
  const serviceGroups = [
    {
      title: 'Accounts & Deposits',
      items: [
        { icon: <FileText size={20} />, label: 'Open Fixed Deposit' },
        { icon: <FileText size={20} />, label: 'Open Recurring Deposit' },
        { icon: <FileText size={20} />, label: 'Download Statement' }
      ]
    },
    {
      title: 'Card Services',
      items: [
        { icon: <CreditCard size={20} />, label: 'Manage Debit Cards' },
        { icon: <CreditCard size={20} />, label: 'Apply for Credit Card' },
        { icon: <CreditCard size={20} />, label: 'Block Card' }
      ]
    },
    {
      title: 'Security & Settings',
      items: [
        { icon: <Shield size={20} />, label: 'Change MPIN' },
        { icon: <Shield size={20} />, label: 'Change Login Password' },
        { icon: <Settings size={20} />, label: 'Transaction Limits' }
      ]
    }
  ];

  return (
    <div className="union-services" data-testid="UNION-SERVICES">
      <Header title="Services" showBack />
      
      <div className="services-content">
        {serviceGroups.map((group, idx) => (
          <div key={idx} className="service-group">
            <h3>{group.title}</h3>
            <div className="service-list">
              {group.items.map((item, i) => (
                <div key={i} className="service-item">
                  <div className="service-item-left">
                    <div className="service-icon">{item.icon}</div>
                    <span>{item.label}</span>
                  </div>
                  <ChevronRight size={20} color="var(--color-text-secondary)" />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
