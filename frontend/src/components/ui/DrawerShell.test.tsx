import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import DrawerShell from './DrawerShell';

/**
 * None of the five overlay implementations this replaces had a focus trap, a
 * focus restore, or a scroll lock, and only two handled Escape. For a keyboard
 * or screen-reader user that made a drawer a visual overlay and nothing more.
 */

afterEach(() => {
  document.body.style.overflow = '';
});

function Drawer(props: Partial<React.ComponentProps<typeof DrawerShell>> = {}) {
  return (
    <DrawerShell open onClose={() => {}} title="Evidence" {...props}>
      <button type="button">first</button>
      <button type="button">second</button>
    </DrawerShell>
  );
}

describe('DrawerShell', () => {
  it('renders nothing when closed', () => {
    const { container } = render(
      <DrawerShell open={false} onClose={() => {}} title="Evidence">
        <p>body</p>
      </DrawerShell>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('is an accessible modal dialog labelled by its title', () => {
    render(<Drawer />);
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByRole('heading', { name: 'Evidence' })).toBeInTheDocument();
  });

  it('closes on Escape', () => {
    const onClose = vi.fn();
    render(<Drawer onClose={onClose} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('closes on backdrop click', () => {
    const onClose = vi.fn();
    const { container } = render(<Drawer onClose={onClose} />);
    const backdrop = container.querySelector('[aria-hidden]');
    fireEvent.click(backdrop!);
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('moves focus into the drawer on open', () => {
    render(<Drawer />);
    expect(screen.getByRole('dialog')).toHaveFocus();
  });

  it('restores focus to whatever opened it', () => {
    const opener = document.createElement('button');
    document.body.appendChild(opener);
    opener.focus();
    expect(opener).toHaveFocus();

    const { unmount } = render(<Drawer />);
    expect(opener).not.toHaveFocus();

    unmount();
    expect(opener).toHaveFocus();
    opener.remove();
  });

  it('does not throw when the opener has left the document', () => {
    const opener = document.createElement('button');
    document.body.appendChild(opener);
    opener.focus();

    const { unmount } = render(<Drawer />);
    opener.remove();
    expect(() => unmount()).not.toThrow();
  });

  it('locks page scroll while open and releases it on close', () => {
    const { unmount } = render(<Drawer />);
    expect(document.body.style.overflow).toBe('hidden');
    unmount();
    expect(document.body.style.overflow).not.toBe('hidden');
  });

  it('wraps Tab from the last focusable back to the first', () => {
    render(<Drawer />);
    const buttons = screen.getAllByRole('button');
    const last = buttons[buttons.length - 1];
    const first = buttons[0];

    last.focus();
    fireEvent.keyDown(document, { key: 'Tab' });
    expect(first).toHaveFocus();
  });

  it('wraps Shift+Tab from the first focusable to the last', () => {
    render(<Drawer />);
    const buttons = screen.getAllByRole('button');
    const first = buttons[0];
    const last = buttons[buttons.length - 1];

    first.focus();
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(last).toHaveFocus();
  });

  it('offers a back affordance only when one was supplied', () => {
    const { rerender } = render(<Drawer />);
    expect(screen.queryByRole('button', { name: /back/i })).not.toBeInTheDocument();

    const onBack = vi.fn();
    rerender(<Drawer onBack={onBack} />);
    const back = screen.getByRole('button', { name: /back/i });
    fireEvent.click(back);
    expect(onBack).toHaveBeenCalledOnce();
  });

  it('renders a footer when given one', () => {
    render(<Drawer footer={<span>ledger link</span>} />);
    expect(screen.getByText('ledger link')).toBeInTheDocument();
  });
});
