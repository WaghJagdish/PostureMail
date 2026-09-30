import "@testing-library/jest-dom";
import { vi } from "vitest";

// Mock ResizeObserver for Recharts and TanStack Virtual
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// Mock clipboard
Object.assign(navigator, {
  clipboard: {
    writeText: vi.fn().mockImplementation(() => Promise.resolve()),
  },
});

// Mock getBoundingClientRect and offsetHeight for virtualized lists in jsdom
Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
  configurable: true,
  value: 600,
});
Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
  configurable: true,
  value: 1200,
});
Object.defineProperty(HTMLElement.prototype, "clientHeight", {
  configurable: true,
  value: 600,
});
Object.defineProperty(HTMLElement.prototype, "clientWidth", {
  configurable: true,
  value: 1200,
});

HTMLElement.prototype.getBoundingClientRect = function () {
  return {
    width: 1200,
    height: 600,
    top: 0,
    left: 0,
    bottom: 600,
    right: 1200,
    x: 0,
    y: 0,
    toJSON: () => {},
  };
};
