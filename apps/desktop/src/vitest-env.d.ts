/* eslint-disable */
import 'vitest';
import '@testing-library/jest-dom';

declare module 'vitest' {
  interface Assertion<T = any> extends any {
    toBeInTheDocument(): void;
  }
}

// Define global types for tests
declare const jest: any;
declare const expect: any;
declare const vi: any;
