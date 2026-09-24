import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';

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
import Services from './screens/Services';
import { AppLayerProvider } from './components/layout/AppLayerContext';
import './components/primitives/Modal.css';
import './components/primitives/Toast.css';

export default function App() {
  return (
    <BrowserRouter>
      <AppLayerProvider>
        <Routes>
        <Route path="/" element={<Navigate to="/splash" replace />} />
        <Route path="/splash" element={<Splash />} />
        <Route path="/login" element={<Login />} />
        <Route path="/mpin" element={<MPIN />} />
        
        <Route element={<AppShell />}>
          <Route path="/home" element={<Home />} />
          <Route path="/accounts" element={<Accounts />} />
          <Route path="/accounts/:id" element={<AccountDetails />} />
          <Route path="/accounts/:id/history" element={<TxnHistory />} />
          
          <Route path="/transfer" element={<Transfer />} />
          <Route path="/transfer/amount" element={<Amount />} />
          <Route path="/transfer/review" element={<Review />} />
          <Route path="/transfer/receipt" element={<Receipt />} />
          
          <Route path="/services" element={<Services />} />
          <Route path="/profile" element={<Profile />} />
        </Route>
        </Routes>
      </AppLayerProvider>
    </BrowserRouter>
  );
}
