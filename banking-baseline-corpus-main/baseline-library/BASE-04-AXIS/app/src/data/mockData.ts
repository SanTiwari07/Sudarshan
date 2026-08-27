export const mockAccounts = [
  { id: '1', type: 'SAVINGS', number: '•••• 1234', balance: 45678.90, name: 'SUDARSHAN SHARMA' },
  { id: '2', type: 'CURRENT', number: '•••• 5678', balance: 125000.00, name: 'SUDARSHAN SHARMA' }
];

export const mockTransactions: Record<string, any[]> = {
  '1': [
    { id: 't1', date: '2026-08-10', description: 'UPI/Zomato/123456', amount: -450.00, type: 'DEBIT' },
    { id: 't2', date: '2026-08-09', description: 'NEFT/Salary/Corp', amount: 85000.00, type: 'CREDIT' },
    { id: 't3', date: '2026-08-08', description: 'Amazon India', amount: -2450.00, type: 'DEBIT' }
  ],
  '2': [
    { id: 't4', date: '2026-08-12', description: 'Vendor Payment', amount: -15000.00, type: 'DEBIT' },
    { id: 't5', date: '2026-08-11', description: 'Client Receipt', amount: 50000.00, type: 'CREDIT' }
  ]
};

export const mockPayees = [
  { id: 'p1', name: 'Rahul Verma', vpa: 'rahul@axisbank', bank: 'Axis Bank', initials: 'RV' },
  { id: 'p2', name: 'Priya Singh', account: '•••• 9876', ifsc: 'HDFC0001234', bank: 'HDFC Bank', initials: 'PS' }
];

export const mockUser = {
  name: 'SUDARSHAN SHARMA',
  lastLogin: '12 Aug 2026, 09:41 AM'
};
