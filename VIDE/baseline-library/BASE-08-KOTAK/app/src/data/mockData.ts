export const USER_DATA = {
  name: "Arjun Sharma",
  lastLogin: "12 Aug, 08:30 PM",
  crn: "8111234567"
};

export const ACCOUNTS = [
  {
    id: "acc_1",
    type: "811 Savings Account",
    number: "XXXX XXXX 4567",
    balance: 45280.50,
    status: "Active"
  },
  {
    id: "acc_2",
    type: "Fixed Deposit",
    number: "XXXX XXXX 8901",
    balance: 100000.00,
    status: "Active",
    maturityDate: "15 Oct 2026"
  }
];

export const TRANSACTIONS = [
  { id: "tx_1", date: "12 Aug 2026", description: "Zomato", amount: -450.00, type: "debit", category: "Food" },
  { id: "tx_2", date: "11 Aug 2026", description: "Salary Credit", amount: 85000.00, type: "credit", category: "Salary" },
  { id: "tx_3", date: "10 Aug 2026", description: "Amazon", amount: -2150.00, type: "debit", category: "Shopping" },
  { id: "tx_4", date: "09 Aug 2026", description: "Uber", amount: -350.00, type: "debit", category: "Transport" },
  { id: "tx_5", date: "08 Aug 2026", description: "Swiggy", amount: -210.00, type: "debit", category: "Food" },
];

export const PAYEES = [
  { id: "p1", name: "Priya Sharma", vpa: "priya@okicici", bank: "ICICI Bank" },
  { id: "p2", name: "Rahul Verma", vpa: "rahul@ybl", bank: "Yes Bank" },
  { id: "p3", name: "Electric Bill", vpa: "msebd@billdesk", bank: "BillDesk" }
];
