import { describe, expect, it, vi } from "vitest";
import { checkPwnedPassword, sha1Hex } from "./pwned";

describe("Pwned Passwords k-anonymity check", () => {
  it("sends only the 5-character prefix and matches the suffix locally", async () => {
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    expect(await sha1Hex("password")).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    const fetchRange = vi.fn(async (_prefix: string) => ({
      suffixes: [
        { suffix: "0018A45C4D1DEF81644B54AB7F969B88D65", count: 1 },
        { suffix: "1E4C9B93F3F0682250B6CF8331B7EE68FD8", count: 9659365 },
      ],
    }));
    const result = await checkPwnedPassword("password", fetchRange);
    expect(fetchRange).toHaveBeenCalledWith("5BAA6");
    expect(fetchRange.mock.calls[0][0]).toHaveLength(5);
    expect(result).toEqual({ count: 9659365, prefixSent: "5BAA6" });
  });

  it("reports zero when the suffix is not in the range", async () => {
    const result = await checkPwnedPassword("a long unique passphrase", async () => ({ suffixes: [] }));
    expect(result.count).toBe(0);
  });
});
