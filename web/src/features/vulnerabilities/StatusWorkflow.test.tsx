import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { renderUi } from "../../test/render";
import { StatusWorkflow } from "./StatusWorkflow";
import { statusChoices } from "./workflow";

describe("finding status workflow", () => {
  it("never offers resolved, even if the server's list contains it", () => {
    expect(statusChoices(["confirmed", "resolved", "in_progress"]).map((c) => c.value)).toEqual(["confirmed", "in_progress"]);
    renderUi(
      <StatusWorkflow status="new" allowedStatuses={["accepted_risk", "confirmed", "in_progress", "resolved"]} onSubmit={vi.fn()} />,
    );
    const radios = screen.getAllByRole("radio");
    expect(radios.map((r) => (r as HTMLInputElement).value)).toEqual(["accepted_risk", "confirmed", "in_progress"]);
    expect(screen.queryByRole("radio", { name: /resolved/i })).toBeNull();
    expect(screen.getByText(/There's no "Resolved" option on purpose/)).toBeInTheDocument();
  });

  it("offers only the allowed transitions and submits the chosen one with the note", async () => {
    const onSubmit = vi.fn();
    renderUi(<StatusWorkflow status="confirmed" allowedStatuses={["accepted_risk", "in_progress"]} onSubmit={onSubmit} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("radio", { name: /In progress/ }));
    await user.type(screen.getByRole("textbox", { name: /Note/ }), "Patching tonight");
    await user.click(screen.getByRole("button", { name: "Update status" }));
    expect(onSubmit).toHaveBeenCalledWith({ status: "in_progress", note: "Patching tonight" });
  });

  it("explains that a resolved finding closes by verification", () => {
    renderUi(<StatusWorkflow status="resolved" allowedStatuses={[]} onSubmit={vi.fn()} />);
    expect(screen.queryAllByRole("radio")).toHaveLength(0);
    expect(screen.getByText(/A re-run of the check passed/)).toBeInTheDocument();
  });
});
