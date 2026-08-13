import React, { useState } from 'react';
import { Calculator } from 'lucide-react';

const DecoyLayout: React.FC = () => {
  const [display, setDisplay] = useState('0');
  const [equation, setEquation] = useState('');

  const handleInput = (val: string) => {
    if (display === '0' && val !== '.') {
      setDisplay(val);
    } else {
      setDisplay(display + val);
    }
  };

  const handleClear = () => {
    setDisplay('0');
    setEquation('');
  };

  const calculate = () => {
    if (display === "1337") {
      // Secret code to exit camouflage
      if (window.electronAPI) {
        void window.electronAPI.disableCamouflage();
      }
      return;
    }
    try {
      let expression = display.replace(/×/g, '*').replace(/÷/g, '/');
      // CSP-safe basic calculator
      const tokens = expression.match(/[+\-*/]|\d+\.?\d*/g);
      if (!tokens) throw new Error();
      let result = Number(tokens[0]);
      for (let i = 1; i < tokens.length; i += 2) {
        const op = tokens[i];
        const next = Number(tokens[i + 1]);
        if (op === '+') result += next;
        else if (op === '-') result -= next;
        else if (op === '*') result *= next;
        else if (op === '/') result /= next;
      }
      setEquation(display + ' =');
      setDisplay(String(result));
    } catch {
      setDisplay('Error');
    }
  };

  const buttons = [
    ['C', '±', '%', '÷'],
    ['7', '8', '9', '×'],
    ['4', '5', '6', '-'],
    ['1', '2', '3', '+'],
    ['0', '.', '=']
  ];

  return (
    <div className="w-full h-screen bg-gray-100 flex flex-col font-sans select-none">
      {/* Fake Header */}
      <div className="h-10 bg-gray-200 flex items-center px-4 border-b border-gray-300 [webkit-app-region:drag]">
        <Calculator size={16} className="text-gray-600 mr-2" />
        <span className="text-[13px] text-gray-600 font-medium">Calculator</span>
      </div>

      {/* Calculator Body */}
      <div className="flex-1 p-5 flex flex-col">
        <div className="flex-1 bg-white rounded-xl border border-gray-200 shadow-md flex flex-col overflow-hidden">
          {/* Display */}
          <div className="h-[120px] bg-gray-50 flex flex-col justify-end items-end p-5 border-b border-gray-200">
            <div data-testid="calculator-equation" className="text-sm text-gray-500 min-h-[20px]">{equation}</div>
            <div data-testid="calculator-display" className="text-[48px] text-gray-900 font-light overflow-hidden text-ellipsis whitespace-nowrap w-full text-right">
              {display}
            </div>
          </div>

          {/* Keypad */}
          <div className="flex-1 p-5 flex flex-col gap-3">
            {buttons.map((row, i) => (
              <div key={i} className={`flex gap-3 ${row.length === 3 && i === 4 ? 'flex-1' : ''}`}>
                {row.map((btn) => {
                  const isOperator = ['÷', '×', '-', '+', '='].includes(btn);
                  const isFunction = ['C', '±', '%'].includes(btn);

                  return (
                    <button
                      key={btn}
                      onClick={() => {
                        if (btn === 'C') handleClear();
                        else if (btn === '=') calculate();
                        else handleInput(btn);
                      }}
                      className={`
                        flex-[${btn === '0' ? '2' : '1'}]
                        border-none rounded-lg text-xl font-medium cursor-pointer shadow-sm border-b border-gray-300 transition-active active:translate-y-[1px]
                        ${isOperator ? 'bg-orange-500 text-white active:bg-orange-600' :
                          isFunction ? 'bg-gray-200 text-gray-900 active:bg-gray-300' :
                          'bg-white text-gray-900 active:bg-gray-100'}
                      `}
                      style={{ flex: btn === '0' ? 2 : 1 }}
                    >
                      {btn}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DecoyLayout;
