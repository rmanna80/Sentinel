import { describe, expect, it } from "vitest";
import { parseIocText } from "./api";

describe("IOC import parsing", () => {
  it("accepts hashes with optional labels and reports bad lines", () => {
    const a = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const { items, invalid } = parseIocText(`${a.toUpperCase()}, empty file\n# comment\nnot-a-hash\n${a}\n`);
    expect(items).toEqual([{ sha256: a, label: "empty file" }]);
    expect(invalid).toEqual(["not-a-hash"]);
  });
});
