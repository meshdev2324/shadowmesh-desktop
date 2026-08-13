# Building and Testing ShadowMesh Desktop (Tauri)

This document provides instructions on how to build and test the ShadowMesh Desktop application.

## Prerequisites

- **Node.js**: v18 or later
- **Rust**: Latest stable version
- **Tauri CLI**: (Optional) `npm install -g @tauri-apps/cli`

## Setup

Install the required Node.js dependencies:

```bash
cd desktop-tauri
npm install
```

## Development

To run the application in development mode with hot-reloading:

```bash
npm run dev
```

This will start the Vite frontend dev server and the Tauri rust backend.

## Building for Production

To create a production-ready bundle:

```bash
npm run build
```

The output will be located in `src-tauri/target/release/bundle/`.

## Testing

### 1. Frontend Unit Tests (Vitest)
These tests cover the React components and business logic in the renderer process.

```bash
npm run test
```

### 2. Rust Unit Tests (Cargo)
These tests cover the Tauri commands and backend logic.

```bash
cd src-tauri
cargo test
```

### 3. End-to-End (E2E) Tests (Playwright)
These tests run the application and simulate user interactions.

```bash
# First, ensure playwright browsers are installed
npx playwright install

# Run E2E tests
npm run test:e2e
```

## Integration with Daemon
The desktop app communicates with the `daemon-rust` service via IPC. For full functionality during testing/development, ensure the daemon is running:

```bash
cd daemon-rust
cargo run
```
