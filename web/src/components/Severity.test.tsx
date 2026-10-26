import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderUi } from "../test/render";
import { SEVERITIES } from "../lib/severity";
import { SeverityBadge } from "./Severity";

describe("SeverityBadge", () => {
  it.each([
    ["critical", "Critical"],
    ["high", "High"],
    ["medium", "Medium"],
    ["low", "Low"],
    ["info", "Info"],
    ["informational", "Info"],
    ["HIGH", "High"],
  ])("labels %s as %s in text, not color alone", (value, label) => {
    renderUi(<SeverityBadge severity={value} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("gives every severity a distinct label and a level glyph", () => {
    const { container } = renderUi(
      <div>
        {SEVERITIES.map((s) => (
          <SeverityBadge key={s} severity={s} />
        ))}
      </div>,
    );
    const labels = SEVERITIES.map((s) => container.querySelector(`[data-sev="${s}"] span`)?.textContent);
    expect(new Set(labels).size).toBe(SEVERITIES.length);
    expect(container.querySelectorAll("svg[aria-hidden='true']").length).toBe(SEVERITIES.length);
  });

  it("says so when the severity is unknown", () => {
    renderUi(<SeverityBadge severity="weird" />);
    expect(screen.getByText("Severity: weird")).toBeInTheDocument();
    renderUi(<SeverityBadge severity={null} />);
    expect(screen.getByText("Severity unknown")).toBeInTheDocument();
  });
});
