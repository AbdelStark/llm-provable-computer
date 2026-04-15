#!/usr/bin/env node

import { chromium } from "playwright";

const url = process.argv[2];

if (!url) {
  console.error("Usage: node render_page_with_playwright.mjs <https-url>");
  process.exit(2);
}

async function launchBrowser() {
  try {
    return await chromium.launch({ headless: true, channel: "chrome" });
  } catch (error) {
    return await chromium.launch({ headless: true });
  }
}

let browser;
try {
  browser = await launchBrowser();
  const context = await browser.newContext({
    userAgent: "codex-paper-archiver",
    viewport: { width: 1440, height: 2000 },
    locale: "en-US",
  });
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 90000 });
  try {
    await page.waitForLoadState("networkidle", { timeout: 15000 });
  } catch {
    // Some sites keep long-lived connections open; DOM content is still useful.
  }
  await page.waitForTimeout(1500);
  const payload = {
    title: await page.title(),
    html: await page.content(),
    text: await page.evaluate(() => document.body?.innerText ?? ""),
  };
  process.stdout.write(JSON.stringify(payload));
  await context.close();
  await browser.close();
} catch (error) {
  if (browser) {
    try {
      await browser.close();
    } catch {}
  }
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
}
