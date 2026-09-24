
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Bell } from 'lucide-react';
import './Header.css';

interface HeaderProps {
  title?: string;
  showBack?: boolean;
  showNotifications?: boolean;
  onBack?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ title, showBack, showNotifications, onBack }) => {
  const navigate = useNavigate();

  const handleBack = () => {
    if (onBack) onBack();
    else navigate(-1);
  };

  return (
    <header className="app-header">
      <div className="header-left">
        {showBack && (
          <button className="icon-btn" onClick={handleBack}>
            <ArrowLeft size={24} />
          </button>
        )}
      </div>
      
      <div className="header-title">
        {title && <h1>{title}</h1>}
      </div>

      <div className="header-right">
        {showNotifications && (
          <button className="icon-btn">
            <Bell size={24} />
          </button>
        )}
      </div>
    </header>
  );
};
