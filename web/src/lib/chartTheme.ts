import { useComputedColorScheme } from "@mantine/core";
import { SEVERITY_COLORS } from "./severity";

/*
 * Chart colors as hex (SVG attributes don't resolve CSS variables everywhere).
 * Device series: three hues validated together (all pairs) for color-vision deficiency on each surface:
 *   dark  #7C89F5, #C98500, #1FA07A on #171C1B; light #4B57C7, #A87400, #16906A on #FFFFFF.
 * More than three devices never get generated hues; the chart asks for a single device instead.
 */
const CHART = {
  dark: {
    surface: "#171C1B",
    grid: "#2A3230",
    axis: "#3A4441",
    tick: "#8E9A96",
    text: "#E4E9E7",
    muted: "#8E9A96",
    accent: "#8C98FF",
    accentWash: "rgba(140, 152, 255, 0.12)",
    threshold: "#B4BFBB",
    series: ["#7C89F5", "#C98500", "#1FA07A"],
  },
  light: {
    surface: "#FFFFFF",
    grid: "#E3E8E6",
    axis: "#C2CAC7",
    tick: "#5F6A67",
    text: "#141918",
    muted: "#5F6A67",
    accent: "#4B57C7",
    accentWash: "rgba(75, 87, 199, 0.1)",
    threshold: "#3F4947",
    series: ["#4B57C7", "#A87400", "#16906A"],
  },
} as const;

export type ChartColors = (typeof CHART)["dark" | "light"] & { severity: (typeof SEVERITY_COLORS)["dark"] };

export const MAX_SERIES = 3;

export function useChartColors(): ChartColors {
  const scheme = useComputedColorScheme("dark");
  return { ...CHART[scheme], severity: SEVERITY_COLORS[scheme] };
}
