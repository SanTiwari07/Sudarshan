import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './styles/tokens.css';

// Layout
import { AppShell } from './components/layout/AppShell';

// Screens
import Splash from './screens/Splash';
import Login from './screens/Login';
import MPIN from './screens/MPIN';
import Home from './screens/Home';
import Accounts from './screens/Accounts';
import AccountDetails from './screens/AccountDetails';
import TxnHistory from './screens/TxnHistory';
import Transfer from './screens/Transfer';
import Amount from './screens/Amount';
import Review from './screens/Review';
import Receipt from './screens/Receipt';
import Profile from './screens/Profile';

const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Splash />} />
        <Route path="/login" element={<Login />} />
        <Route path="/mpin" element={<MPIN />} />
        
        <Route element={<AppShell />}>
          <Route path="/home" element={<Home />} />
          
          <Route path="/accounts" element={<Accounts />} />
          <Route path="/accounts/:id" element={<AccountDetails />} />
          <Route path="/accounts/:id/transactions" element={<TxnHistory />} />
          
          <Route path="/transfer" element={<Transfer />} />
          <Route path="/transfer/amount" element={<Amount />} />
          <Route path="/transfer/review" element={<Review />} />
          <Route path="/transfer/receipt" element={<Receipt />} />
          
          <Route path="/profile" element={<Profile />} />
        </Route>
        
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
