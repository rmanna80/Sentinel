import { createTheme, type MantineColorsTuple } from "@mantine/core";

/*
 * Sentinel's palette: graphite with a green cast (instrument panel), an iris accent kept apart from every
 * severity hue, and severity colors chosen for >= 4.5:1 text contrast on each surface in both schemes.
 * The CSS variables in styles/tokens.css carry the same values for hand-written CSS.
 */

const iris: MantineColorsTuple = [
  "#EEF0FF", "#DDE1FF", "#BCC3FF", "#A3ADFF", "#8C98FF",
  "#7482F2", "#5864DB", "#4B57C7", "#3D47A6", "#2F3782",
];

// Dark scheme ramp (Mantine reads text from 0, dimmed from 2, borders from 4, inputs 6, body 7).
const dark: MantineColorsTuple = [
  "#E4E9E7", "#B4BFBB", "#8E9A96", "#66716D", "#38413F",
  "#2A3230", "#1D2322", "#171C1B", "#121615", "#0C0F0E",
];

// Light scheme neutrals with the same green cast.
const gray: MantineColorsTuple = [
  "#F5F7F6", "#EEF1F0", "#E3E8E6", "#D5DBD9", "#C2CAC7",
  "#9AA5A1", "#5F6A67", "#3F4947", "#262D2B", "#141918",
];

export const FONT_SANS =
  "'Atkinson Hyperlegible Next Variable', 'Atkinson Hyperlegible Next', system-ui, -apple-system, 'Segoe UI', sans-serif";
export const FONT_MONO =
  "'Atkinson Hyperlegible Mono Variable', 'Atkinson Hyperlegible Mono', ui-monospace, 'Cascadia Mono', Consolas, monospace";

export const theme = createTheme({
  primaryColor: "iris",
  primaryShade: { light: 7, dark: 6 },
  autoContrast: true,
  luminanceThreshold: 0.32,
  colors: { iris, dark, gray },
  white: "#FFFFFF",
  black: "#141918",
  fontFamily: FONT_SANS,
  fontFamilyMonospace: FONT_MONO,
  fontSmoothing: true,
  focusRing: "auto",
  respectReducedMotion: true,
  cursorType: "pointer",
  defaultRadius: "sm",
  radius: { xs: "3px", sm: "5px", md: "7px", lg: "10px", xl: "14px" },
  fontSizes: { xs: "0.75rem", sm: "0.8125rem", md: "0.875rem", lg: "1rem", xl: "1.25rem" },
  lineHeights: { xs: "1.4", sm: "1.45", md: "1.5", lg: "1.5", xl: "1.4" },
  spacing: { xs: "6px", sm: "10px", md: "16px", lg: "24px", xl: "32px" },
  headings: {
    fontFamily: FONT_SANS,
    fontWeight: "650",
    textWrap: "balance",
    sizes: {
      h1: { fontSize: "1.5rem", lineHeight: "1.25" },
      h2: { fontSize: "1.125rem", lineHeight: "1.3" },
      h3: { fontSize: "0.9375rem", lineHeight: "1.35" },
      h4: { fontSize: "0.8125rem", lineHeight: "1.4" },
    },
  },
  components: {
    Button: { defaultProps: { size: "sm", fw: 600 } },
    TextInput: { defaultProps: { size: "sm" } },
    PasswordInput: { defaultProps: { size: "sm" } },
    Select: { defaultProps: { size: "sm", allowDeselect: false, comboboxProps: { shadow: "md" } } },
    Tooltip: { defaultProps: { withArrow: true, openDelay: 250, multiline: true, maw: 360 } },
    Modal: { defaultProps: { centered: true, radius: "md", overlayProps: { backgroundOpacity: 0.6, blur: 2 } } },
    Table: { defaultProps: { verticalSpacing: 7, horizontalSpacing: "md", highlightOnHover: true } },
  },
});
