/**
 * Capture the dashboard screenshots used in the documentation.
 *
 * Usage:  BASE=http://127.0.0.1:8000 ALERT=<uuid> node shots.mjs
 *
 * Committed so the images can be regenerated rather than re-staged by hand:
 * a screenshot nobody can reproduce goes stale the first time the UI changes,
 * and nobody notices because it still looks plausible.
 */
import puppeteer from "puppeteer-core";
import { mkdirSync } from "node:fs";

const BASE = process.env.BASE || "http://127.0.0.1:8000";
const OUT = process.env.OUT || "../docs/images";
const ALERT = process.env.ALERT || "";
const CHROME =
  process.env.CHROME || "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";

mkdirSync(OUT, { recursive: true });

const browser = await puppeteer.launch({
  executablePath: CHROME,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

const pages = [
  ["overview", "/dashboard/"],
  ["alerts", "/dashboard/alerts"],
  ["rules", "/dashboard/rules"],
];
if (ALERT) pages.push(["alert-detail", `/dashboard/alerts/${ALERT}`]);

for (const theme of ["light", "dark"]) {
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 2 });
  // Set before any navigation, so the pre-paint theme script reads it.
  await page.evaluateOnNewDocument((value) => {
    window.localStorage.setItem("nd-theme", value);
  }, theme);

  for (const [name, path] of pages) {
    await page.goto(BASE + path, { waitUntil: "networkidle0", timeout: 60000 });
    await new Promise((resolve) => setTimeout(resolve, 2500));
    const suffix = theme === "light" ? "" : "-dark";
    await page.screenshot({ path: `${OUT}/dashboard-${name}${suffix}.png` });
    console.log("wrote", `dashboard-${name}${suffix}`);
  }
  await page.close();
}

await browser.close();
