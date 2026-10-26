import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderUi } from "../../test/render";
import { ScoreCard } from "./ScoreCard";

const basis =
  "100 minus 20 per critical, 8 per high, 3 per medium and 1 per low open finding (verified, or heuristic at high confidence). Shown only when at least 75% of applicable checks completed.";

describe("ScoreCard", () => {
  it('shows "Incomplete" and the coverage, never a number, when the score is null', () => {
    renderUi(
      <ScoreCard score={null} rawScore={92} coverage={0.5} checksCompleted={3} checksApplicable={6} threatLevel="high" scoreBasis={basis} />,
    );
    const value = screen.getByTestId("score-value");
    expect(value).toHaveTextContent("Incomplete");
    expect(value.textContent).not.toMatch(/\d/);
    expect(screen.getByText(/Only 3 of 6 applicable checks completed \(50%\)/)).toBeInTheDocument();
    expect(screen.getByText(/A score needs at least 75%/)).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: "Check coverage" })).toHaveAttribute("aria-valuenow", "50");
  });

  it("explains a missing posture scan when nothing has run", () => {
    renderUi(
      <ScoreCard score={null} rawScore={100} coverage={null} checksCompleted={0} checksApplicable={0} threatLevel="informational" scoreBasis={basis} />,
    );
    expect(screen.getByTestId("score-value")).toHaveTextContent("Incomplete");
    expect(screen.getByText(/No posture scan has finished yet/)).toBeInTheDocument();
    expect(screen.getByText("Informational")).toBeInTheDocument();
  });

  it("shows the score when coverage is sufficient", () => {
    renderUi(
      <ScoreCard score={84} rawScore={84} coverage={0.9} checksCompleted={9} checksApplicable={10} threatLevel="medium" scoreBasis={basis} />,
    );
    expect(screen.getByTestId("score-value")).toHaveTextContent("84/ 100");
    expect(screen.getByText("Medium")).toBeInTheDocument();
  });
});
