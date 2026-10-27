import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { FeedStatus } from "../../api/types";
import { renderUi } from "../../test/render";
import { FeedSummary } from "./FeedSummary";

function makeStatus(overrides: Partial<FeedStatus> = {}): FeedStatus {
  return {
    enabled: true,
    outbound_enabled: true,
    last_synced_at: null,
    status: "ok",
    detail: null,
    total: 0,
    new_count: 0,
    matched_open: 0,
    pinned: 0,
    note: "",
    ...overrides,
  };
}

describe("FeedSummary", () => {
  it("shows a call-to-action to Integrations when the feed is off", () => {
    renderUi(<FeedSummary status={makeStatus({ enabled: false })} />);
    const cta = screen.getByRole("link", { name: /Turn on the Hacker News feed under Integrations/i });
    expect(cta).toHaveAttribute("href", "/integrations");
    // No refresh button is offered while the feed is off.
    expect(screen.queryByRole("button", { name: /Refresh now/i })).toBeNull();
  });

  it("shows counts and a refresh button when the feed is on", () => {
    renderUi(<FeedSummary status={makeStatus({ total: 12, new_count: 3 })} onRefresh={() => {}} />);
    expect(screen.queryByText(/Turn on the Hacker News feed/i)).toBeNull();
    expect(screen.getByRole("button", { name: /Refresh now/i })).toBeEnabled();
  });

  it("disables refresh when outbound connections are off", () => {
    renderUi(<FeedSummary status={makeStatus({ outbound_enabled: false })} onRefresh={() => {}} />);
    expect(screen.getByRole("button", { name: /Refresh now/i })).toBeDisabled();
  });
});
