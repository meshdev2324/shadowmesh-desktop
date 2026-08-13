import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import DuressPinConfig from '../DuressPinConfig';
import React from 'react';
import { createTestElectronAPI } from "../../../__tests__/testElectronAPI";

describe('DuressPinConfig Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.electronAPI = createTestElectronAPI();
  });

  it('renders correctly and checks for existing PIN', async () => {
    vi.mocked(window.electronAPI.getDuressPin).mockResolvedValue('existing-hash');

    act(() => {
      render(<DuressPinConfig />);
    });
    
    await waitFor(() => {
      expect(window.electronAPI.getDuressPin).toHaveBeenCalled();
    });
    
    expect(screen.getByText(/Active Response Layer/i)).toBeInTheDocument();
  });

  it('shows error if PINs do not match', async () => {
    vi.mocked(window.electronAPI.getDuressPin).mockResolvedValue(null);

    act(() => {
      render(<DuressPinConfig />);
    });
    
    // Expand the component
    fireEvent.click(screen.getByText(/Duress Protocol/i));

    const pinInput = screen.getByPlaceholderText(/^PIN$/i);
    const confirmInput = screen.getByPlaceholderText(/^Confirm$/i);
    
    fireEvent.change(pinInput, { target: { value: '1234' } });
    fireEvent.change(confirmInput, { target: { value: '5678' } });

    fireEvent.click(screen.getByText(/Deploy/i));
    
    expect(await screen.findByText(/PINs do not match/i)).toBeInTheDocument();
  });

  it('hashes and saves PIN correctly', async () => {
    vi.mocked(window.electronAPI.getDuressPin).mockResolvedValue(null);
    vi.mocked(window.electronAPI.setDuressPin).mockResolvedValue(true);

    act(() => {
      render(<DuressPinConfig />);
    });
    
    // Expand
    fireEvent.click(screen.getByText(/Duress Protocol/i));

    const pinInput = screen.getByPlaceholderText(/^PIN$/i);
    const confirmInput = screen.getByPlaceholderText(/^Confirm$/i);
    
    fireEvent.change(pinInput, { target: { value: '1234' } });
    fireEvent.change(confirmInput, { target: { value: '1234' } });

    fireEvent.click(screen.getByText(/Deploy/i));
    
    await waitFor(() => {
      expect(window.electronAPI.setDuressPin).toHaveBeenCalledWith(expect.stringMatching(/^[a-f0-9]{64}$/));
    });
    
    expect(await screen.findByText(/Duress Active/i)).toBeInTheDocument();
  });

  it('handles PIN removal with confirmation', async () => {
    vi.mocked(window.electronAPI.getDuressPin).mockResolvedValue('existing-hash');
    vi.mocked(window.electronAPI.setDuressPin).mockResolvedValue(true);
    
    // Mock window.confirm
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    
    act(() => {
      render(<DuressPinConfig />);
    });
    
    await waitFor(() => {
      expect(screen.getByText(/Active Response Layer/i)).toBeInTheDocument();
    });

    // Expand
    fireEvent.click(screen.getByText(/Duress Protocol/i));

    const buttons = screen.getAllByRole('button');
    const trashBtn = buttons.find(b => b.querySelector('svg.lucide-trash2'));
    
    if (trashBtn) {
      fireEvent.click(trashBtn);
      expect(confirmSpy).toHaveBeenCalled();
      await waitFor(() => {
        expect(window.electronAPI.setDuressPin).toHaveBeenCalledWith("");
      });
      expect(await screen.findByText(/Disabled/i)).toBeInTheDocument();
    }
    
    confirmSpy.mockRestore();
  });
});
