export const mockUser = {
  name: 'Rahul Sharma',
  lastLogin: '13 Aug 2026, 10:30 AM',
  accounts: [
    {
      id: 'ACC-001',
      type: 'Savings Account',
      number: 'XXXX XXXX 1234',
      balance: 145000.50,
      currency: 'INR'
    },
    {
      id: 'ACC-002',
      type: 'Current Account',
      number: 'XXXX XXXX 5678',
      balance: 25000.00,
      currency: 'INR'
    }
  ],
  transactions: [
    {
      id: 'TXN-001',
      date: '12 Aug 2026',
      description: 'Amazon Shopping',
      amount: -1250.00,
      type: 'debit',
      category: 'Shopping'
    },
    {
      id: 'TXN-002',
      date: '10 Aug 2026',
      description: 'Salary Credit',
      amount: 85000.00,
      type: 'credit',
      category: 'Income'
    }
  ]
};
