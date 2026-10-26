import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => cleanup());

// jsdom lacks these browser APIs that Mantine uses.
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver ?? (ResizeObserverStub as unknown as typeof ResizeObserver);
window.HTMLElement.prototype.scrollIntoView = window.HTMLElement.prototype.scrollIntoView ?? function () {};

// Mantine's autosize textarea listens for font loading.
if (!("fonts" in document)) {
  Object.defineProperty(document, "fonts", {
    value: { addEventListener: () => {}, removeEventListener: () => {}, ready: Promise.resolve() },
  });
}
