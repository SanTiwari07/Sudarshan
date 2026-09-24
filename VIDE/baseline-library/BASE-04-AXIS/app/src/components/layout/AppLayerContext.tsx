import React, { createContext, useContext, useState } from 'react';
import type { ReactNode } from 'react';

interface ToastState {
  message: string;
  type: 'success' | 'error' | 'info';
}

interface ModalState {
  title: string;
  content: ReactNode;
  onConfirm?: () => void;
  confirmText?: string;
}

interface AppLayerContextType {
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void;
  showModal: (modal: ModalState) => void;
  hideModal: () => void;
}

const AppLayerContext = createContext<AppLayerContextType | undefined>(undefined);

export const useAppLayer = () => {
  const context = useContext(AppLayerContext);
  if (!context) throw new Error('useAppLayer must be used within AppLayerProvider');
  return context;
};

export const AppLayerProvider: React.FC<{children: ReactNode}> = ({ children }) => {
  const [toast, setToast] = useState<ToastState | null>(null);
  const [modal, setModal] = useState<ModalState | null>(null);

  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setToast({ message, type });
  };

  const showModal = (modalState: ModalState) => {
    setModal(modalState);
  };

  const hideModal = () => {
    setModal(null);
  };

  return (
    <AppLayerContext.Provider value={{ showToast, showModal, hideModal }}>
      {children}
      {toast && (
        <div style={{position: 'absolute', bottom: '80px', left: 0, right: 0, zIndex: 9999, display: 'flex', justifyContent: 'center'}}>
          <div className={`toast toast-${toast.type}`} onClick={() => setToast(null)}>
            {toast.message}
          </div>
        </div>
      )}
      {modal && (
        <div className="modal-overlay" onClick={hideModal}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{modal.title}</h2>
              <button className="icon-btn" onClick={hideModal}>✕</button>
            </div>
            <div className="modal-body">
              {modal.content}
            </div>
            {modal.onConfirm && (
              <div className="modal-footer">
                <button className="btn btn-secondary btn-full" onClick={hideModal}>Cancel</button>
                <button className="btn btn-primary btn-full" onClick={() => { modal.onConfirm!(); hideModal(); }}>
                  {modal.confirmText || 'Confirm'}
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </AppLayerContext.Provider>
  );
};
