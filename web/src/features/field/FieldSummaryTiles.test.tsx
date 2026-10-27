import { describe, expect, it } from "vitest";
import type { FieldSummary } from "../../api/types";
import { renderUi } from "../../test/render";
import { FieldSummaryTiles } from "./FieldSummaryTiles";

function makeSummary(overrides: Partial<FieldSummary> = {}): FieldSummary {
  return {
    captures: 2,
    access_points: 18,
    rogue_suspects: 0,
    weak_own: 0,
    own: 4,
    unknown: 9,
    known_networks: { own_ssids: [], own_bssids: [] },
    note: "",
    ...overrides,
  };
}

function tileFor(container: HTMLElement, label: string): HTMLElement | null {
  const labels = Array.from(container.querySelectorAll("div"));
  const labelEl = labels.find((el) => el.textContent === label);
  return (labelEl?.parentElement as HTMLElement) ?? null;
}

describe("FieldSummaryTiles", () => {
  it("highlights rogue suspects in danger when any are present", () => {
    const { container } = renderUi(<FieldSummaryTiles summary={makeSummary({ rogue_suspects: 2 })} />);
    const tile = tileFor(container, "Rogue suspects");
    expect(tile).not.toBeNull();
    expect(tile).toHaveAttribute("data-highlight", "danger");
  });

  it("highlights your own weak networks in warn when any are present", () => {
    const { container } = renderUi(<FieldSummaryTiles summary={makeSummary({ weak_own: 1 })} />);
    expect(tileFor(container, "Your weak networks")).toHaveAttribute("data-highlight", "warn");
  });

  it("does not highlight anything when counts are zero", () => {
    const { container } = renderUi(<FieldSummaryTiles summary={makeSummary()} />);
    expect(container.querySelector("[data-highlight]")).toBeNull();
  });
});
