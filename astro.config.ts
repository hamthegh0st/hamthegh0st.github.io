import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import sitemap from "@astrojs/sitemap";
export default defineConfig({site:"https://hamthegh0st.github.io",integrations:[mdx(),sitemap()]});
