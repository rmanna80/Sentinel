import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { AdvisoryOut } from "../../api/types";
import { renderUi } from "../../test/render";
import { AdvisoryCard } from "./AdvisoryCard";

function makeAdvisory(overrides: Partial<AdvisoryOut> = {}): AdvisoryOut {
  return {
    id: 1,
    source: "hackernews",
    title: "OpenSSL patch released",
    url: "https://example.com/openssl",
    summary: "A new OpenSSL release fixes a buffer overflow.",
    author: "dang",
    score: 142,
    tags: ["openssl", "patch"],
    cve_ids: ["CVE-2026-0001"],
    matched: false,
    match_detail: {},
    severity_hint: "high",
    suggested_coverage: null,
    status: "new",
    published_at: null,
    fetched_at: null,
    read_at: null,
    ...overrides,
  };
}

describe("AdvisoryCard", () => {
  it("shows the severity_hint as a labelled chip, not color alone", () => {
    renderUi(<AdvisoryCard advisory={makeAdvisory({ severity_hint: "high" })} onOpen={vi.fn()} />);
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("renders the title as a safe external link for an http(s) url", () => {
    renderUi(<AdvisoryCard advisory={makeAdvisory()} onOpen={vi.fn()} />);
    const link = screen.getByRole("link", { name: /OpenSSL patch released/ });
    expect(link).toHaveAttribute("href", "https://example.com/openssl");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("never renders a javascript: url as a link", () => {
    renderUi(
      <AdvisoryCard advisory={makeAdvisory({ url: "javascript:alert(1)", title: "Sketchy advisory" })} onOpen={vi.fn()} />,
    );
    // The title is still shown as text, but no anchor is produced for the unsafe scheme.
    expect(screen.getByText("Sketchy advisory")).toBeInTheDocument();
    expect(screen.queryByRole("link")).toBeNull();
    expect(document.querySelector('a[href^="javascript:"]')).toBeNull();
  });

  it("opens the detail drawer when the row body is activated", async () => {
    const onOpen = vi.fn();
    const { getByRole } = renderUi(<AdvisoryCard advisory={makeAdvisory()} onOpen={onOpen} />);
    getByRole("button", { name: /Open advisory: OpenSSL patch released/ }).click();
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});
