import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setCsrfToken } from "../../api/client";
import { renderUi } from "../../test/render";
import { KnownNetworksEditor } from "./KnownNetworksEditor";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("KnownNetworksEditor", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("csrf-test");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    setCsrfToken(null);
  });

  it("surfaces the server's 422 detail when a BSSID isn't a MAC address", async () => {
    fetchMock.mockImplementation(async (_url, init) => {
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "GET") return jsonResponse(200, { own_ssids: [], own_bssids: [] });
      return jsonResponse(422, {
        detail: [{ loc: ["body", "own_bssids", 0], msg: "value is not a valid MAC address" }],
      });
    });

    renderUi(<KnownNetworksEditor />);
    const user = userEvent.setup();

    const bssidInput = await screen.findByPlaceholderText("AA:BB:CC:DD:EE:FF");
    await user.type(bssidInput, "not-a-mac{Enter}");
    await user.click(screen.getByRole("button", { name: /Save networks/i }));

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("own bssids.0: value is not a valid MAC address"),
    );
    // The failing PUT was actually attempted.
    expect(fetchMock.mock.calls.some((c) => (c[1]?.method ?? "GET").toUpperCase() === "PUT")).toBe(true);
  });
});
