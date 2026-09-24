import React from 'react';
import { useNavigate } from 'react-router-dom';

const servicesMap = [
  {
    category: 'Accounts & Deposits',
    items: [
      { id: '1', title: 'Open Savings Account', icon: '🏦' },
      { id: '2', title: 'Fixed Deposit (FD)', icon: '💰' },
      { id: '3', title: 'Recurring Deposit (RD)', icon: '🔄' },
      { id: '4', title: 'Cheque Book Request', icon: '📝' }
    ]
  },
  {
    category: 'Cards',
    items: [
      { id: '5', title: 'Debit Card Management', icon: '💳' },
      { id: '6', title: 'Apply for Credit Card', icon: '💳' },
      { id: '7', title: 'Block Card', icon: '🚫' }
    ]
  },
  {
    category: 'Loans',
    items: [
      { id: '8', title: 'Apply for Home Loan', icon: '🏠' },
      { id: '9', title: 'Apply for Personal Loan', icon: '👤' },
      { id: '10', title: 'Loan Account Details', icon: '📊' }
    ]
  },
  {
    category: 'Investments',
    items: [
      { id: '11', title: 'Mutual Funds', icon: '📈' },
      { id: '12', title: 'PPF Account', icon: '🛡️' },
      { id: '13', title: 'Wealth Management', icon: '💎' }
    ]
  },
  {
    category: 'Other Services',
    items: [
      { id: '14', title: 'Update KYC', icon: '📋' },
      { id: '15', title: 'Positive Pay System', icon: '✔️' },
      { id: '16', title: 'Form 15G/15H', icon: '📄' },
      { id: '17', title: 'Locker Facility', icon: '🔒' }
    ]
  }
];

export const Services: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col h-full bg-[var(--color-bg)]">
      <div className="flex items-center p-4 text-white shadow-md z-10" style={{ backgroundColor: 'var(--color-primary)' }}>
        <button onClick={() => navigate('/home')} className="mr-4 text-xl">
          ←
        </button>
        <h1 className="text-lg font-bold">Services</h1>
      </div>

      <div className="p-4 bg-white shadow-sm mb-2">
        <div className="relative">
          <span className="absolute left-3 top-2.5 text-gray-400">🔍</span>
          <input 
            type="text" 
            placeholder="Search for a service..." 
            className="w-full bg-gray-100 rounded-lg py-2 pl-10 pr-4 outline-none text-sm"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        {servicesMap.map((group, index) => (
          <div key={index}>
            <h3 className="text-sm font-bold text-[var(--color-text-secondary)] mb-3">{group.category}</h3>
            <div className="bg-white rounded-[var(--radius-card)] overflow-hidden shadow-sm">
              {group.items.map((item, itemIndex) => (
                <div key={item.id}>
                  <div className="flex items-center p-4 cursor-pointer hover:bg-gray-50">
                    <span className="text-xl mr-4">{item.icon}</span>
                    <span className="flex-1 text-sm font-medium">{item.title}</span>
                    <span className="text-gray-400">›</span>
                  </div>
                  {itemIndex < group.items.length - 1 && (
                    <div className="w-full h-px bg-[var(--color-divider)] ml-12"></div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
        <div className="pb-8"></div>
      </div>
    </div>
  );
};
