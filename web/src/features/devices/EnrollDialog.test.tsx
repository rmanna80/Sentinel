import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { EnrollmentCode } from "../../api/types";
import { renderUi } from "../../test/render";
import { EnrollmentInstructions, formatCountdown, remainingSeconds } from "./EnrollDialog";

const code: EnrollmentCode = {
  code: "K7QM-2XRP-9TDA",
  expires_at: "2026-10-26T12:15:00Z",
  command: "uv run sentinel-agent enroll --server http://127.0.0.1:8765 --code K7QM-2XRP-9TDA",
};

describe("enrollment instructions", () => {
  it("shows the code and the exact command from the server", () => {
    const now = new Date("2026-10-26T12:00:00Z").getTime();
    renderUi(<EnrollmentInstructions code={code} now={now} />);
    expect(screen.getByTestId("enroll-code")).toHaveTextContent("K7QM-2XRP-9TDA");
    expect(screen.getByTestId("command-text").textContent).toBe(code.command);
    expect(screen.getByRole("timer")).toHaveTextContent("Expires in 15:00");
    expect(screen.getByRole("button", { name: "Copy command" })).toBeInTheDocument();
  });

  it("counts down and then says the code expired", () => {
    expect(remainingSeconds(code.expires_at, new Date("2026-10-26T12:14:05Z").getTime())).toBe(55);
    expect(formatCountdown(55)).toBe("0:55");
    renderUi(<EnrollmentInstructions code={code} now={new Date("2026-10-26T12:16:00Z").getTime()} />);
    expect(screen.getByRole("timer")).toHaveTextContent("This code has expired");
  });
});
