import {
  Button,
  Input,
  Select,
  TextInput,
  createTheme,
  defaultVariantColorsResolver,
  type VariantColorsResolver,
} from "@mantine/core";

export type BrandSettings = {
  name: string;
  logo_url: string;
  favicon_url: string;
  color: string;
  color_strong: string;
  ink: string;
};

export const defaultBrand: BrandSettings = {
  name: "LFP Connect",
  logo_url: "/assets/lfp-connect-auto.svg",
  favicon_url: "/assets/lfp-favicon.svg",
  color: "#ff6f61",
  color_strong: "#e85c50",
  ink: "#0b1426",
};

const brandVariants: VariantColorsResolver = (input) => {
  if (input.color !== "coral") return defaultVariantColorsResolver(input);

  const border = "1px solid transparent";
  if (input.variant === "filled") {
    return {
      background: "var(--color-brand)",
      hover: "var(--color-brand-strong)",
      color: "var(--color-brand-ink)",
      hoverColor: "var(--color-brand-ink)",
      border,
    };
  }
  if (input.variant === "light" || input.variant === "subtle") {
    return {
      background: "color-mix(in srgb, var(--color-brand) 14%, transparent)",
      hover: "var(--color-brand)",
      color: "var(--color-text)",
      hoverColor: "var(--color-brand-ink)",
      border,
    };
  }
  return defaultVariantColorsResolver(input);
};

export const appTheme = createTheme({
  primaryColor: "coral",
  defaultRadius: "md",
  fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
  colors: {
    coral: ["#fff1ef", "#ffe2de", "#ffc4bd", "#ffa59b", "#ff877b", "#ff6f61", "#e85c50", "#c9473d", "#a93730", "#872b26"],
  },
  variantColorResolver: brandVariants,
  components: {
    TextInput: TextInput.extend({ defaultProps: { size: "xs" } }),
    Select: Select.extend({ defaultProps: { size: "xs", allowDeselect: false } }),
    Button: Button.extend({ defaultProps: { size: "xs", color: "coral" } }),
    InputWrapper: Input.Wrapper.extend({ defaultProps: { inputWrapperOrder: ["label", "input", "description", "error"] } }),
  },
});

export function applyBrand(brand: BrandSettings) {
  const root = document.documentElement.style;
  root.setProperty("--color-brand", brand.color);
  root.setProperty("--color-brand-strong", brand.color_strong);
  root.setProperty("--color-brand-ink", brand.ink);
  document.title = `${brand.name} Pipe`;
  const favicon = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
  if (favicon) favicon.href = brand.favicon_url;
}
