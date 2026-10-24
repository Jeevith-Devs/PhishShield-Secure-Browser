/**
 * PhishShield End-to-End Playwright Automated Test Suite
 * Validates all core browser functions:
 * 1. Backend ML inference & Risk Evaluation API
 * 2. Adaptive Interstitial Barrier on phishing targets
 * 3. Synthetic Data Injection (SDI) sandbox containment
 * 4. Evidence-Grounded AI Security Analyst Report generation
 * 5. Full interactive UI flow on the SOC platform
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const ARTIFACT_DIR = path.resolve('C:\\Users\\Admin\\.gemini\\antigravity-ide\\brain\\1cac5cd2-fddf-4218-a6b5-2ac7bc71bfa7');
if (!fs.existsSync(ARTIFACT_DIR)) {
  fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
}

async function runTestSuite() {
  console.log('===============================================================');
  console.log('   PHISHSHIELD AUTOMATED PLAYWRIGHT FUNCTIONAL TEST SUITE     ');
  console.log('===============================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✓ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ✗ FAIL: ${message}`);
      failed++;
    }
  }

  // 1. API Health & ML Core Verification
  console.log('--- Step 1: Validating Backend Intelligence Core ---');
  try {
    const healthRes = await fetch('http://127.0.0.1:8000/health');
    const health = await healthRes.json();
    assert(health.status === 'healthy', 'Backend health is reporting healthy');
    assert(health.components.risk_engine === 'operational', 'Risk Scoring Engine is operational');
    assert(health.components.feature_engine === 'operational', 'URL Feature Engine is operational');
  } catch (err) {
    assert(false, `Backend health check failed: ${err.message}`);
  }

  // 2. ML Inference Verification
  console.log('\n--- Step 2: Validating ML Threat Classifier & Scoring ---');
  try {
    // Test Safe URL
    const safeRes = await fetch('http://127.0.0.1:8000/api/v1/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://www.google.com', client_type: 'browser' }),
    });
    const safeData = await safeRes.json();
    assert(safeData.threat_level === 'LOW', `google.com classified as LOW (got ${safeData.threat_level})`);
    assert(safeData.risk_score <= 30, `google.com risk score <= 30 (got ${safeData.risk_score})`);
    assert(safeData.adaptive_action === 'ALLOW', `google.com action is ALLOW (got ${safeData.adaptive_action})`);

    // Test Phishing URL
    const phishRes = await fetch('http://127.0.0.1:8000/api/v1/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://paypal-verification-account-auth.xyz/login', client_type: 'browser' }),
    });
    const phishData = await phishRes.json();
    assert(
      phishData.threat_level === 'CRITICAL' || phishData.threat_level === 'HIGH',
      `Phishing lure flagged as ${phishData.threat_level} (score: ${phishData.risk_score})`
    );
    assert(phishData.risk_score >= 60, `Phishing risk score >= 60 (got ${phishData.risk_score})`);
    assert(
      phishData.adaptive_action === 'ISOLATE' || phishData.adaptive_action === 'BLOCK',
      `Adaptive enforcement is ${phishData.adaptive_action}`
    );
    assert(phishData.indicators?.reasons?.length > 0, `Detection signals populated (${phishData.indicators?.reasons?.length} reasons)`);
  } catch (err) {
    assert(false, `ML inference verification failed: ${err.message}`);
  }

  // 3. Synthetic Data Injection (SDI) Verification
  console.log('\n--- Step 3: Validating Synthetic Data Injection (SDI) Sandbox ---');
  try {
    const sdiRes = await fetch('http://127.0.0.1:8000/api/v1/sandbox/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: 'https://paypal-verification-account-auth.xyz/login',
        threat_level: 'CRITICAL',
        inject_synthetic_data: true,
      }),
    });
    const sdiData = await sdiRes.json();
    assert(Boolean(sdiData.session_id), `Ephemeral sandbox session provisioned (ID: ${sdiData.session_id?.slice(0, 8)}…)`);
    assert(Boolean(sdiData.synthetic_data?.card_number), `Synthetic ISO/IEC 7812 card injected: ${sdiData.synthetic_data?.card_number}`);
    assert(Boolean(sdiData.synthetic_data?.email), `Honeypot canary email generated: ${sdiData.synthetic_data?.email}`);
    assert(sdiData.synthetic_data?.cardholder_name?.length > 0, `Cardholder name populated: ${sdiData.synthetic_data?.cardholder_name}`);
  } catch (err) {
    assert(false, `SDI sandbox verification failed: ${err.message}`);
  }

  // 4. AI Security Analyst Report Verification
  console.log('\n--- Step 4: Validating AI Security Analyst Report Generation ---');
  try {
    const analystRes = await fetch('http://127.0.0.1:8000/api/v1/analyst/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scan_id: 'test-scan-e2e',
        include_sandbox_telemetry: true,
        include_graph_data: true,
      }),
    });
    const analystData = await analystRes.json();
    assert(Boolean(analystData.executive_summary), 'AI Executive Summary generated');
    assert(Array.isArray(analystData.observed) && analystData.observed.length > 0, `OBSERVED facts generated (${analystData.observed.length} facts)`);
    assert(Array.isArray(analystData.inferred) && analystData.inferred.length > 0, `INFERRED hypotheses generated (${analystData.inferred.length} hypotheses)`);
    assert(Array.isArray(analystData.recommended_actions), `Recommended actions present (${analystData.recommended_actions.length} actions)`);
  } catch (err) {
    assert(false, `AI Analyst report verification failed: ${err.message}`);
  }

  // 5. Browser UI End-to-End Navigation using Playwright
  console.log('\n--- Step 5: Launching Playwright Browser UI Automation ---');
  let browser;
  try {
    // Launch Chrome or Chromium
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
    });
    const page = await context.newPage();

    console.log('  Navigating to SOC Platform at http://localhost:3000...');
    await page.goto('http://localhost:3000', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForTimeout(2000);
    assert(await page.title() !== '', 'Platform dashboard loaded successfully');

    // Screenshot 1: Overview
    const screenshot1 = path.join(ARTIFACT_DIR, 'playwright_01_overview.png');
    await page.screenshot({ path: screenshot1 });
    console.log(`  📸 Saved screenshot: ${screenshot1}`);

    // Click on "Secure Browser" navigation
    console.log('  Clicking on "🛡️ Secure Browser" navigation button...');
    const browserNavBtn = page.locator('button:has-text("Secure Browser")');
    await browserNavBtn.waitFor({ state: 'visible', timeout: 10000 });
    await browserNavBtn.click();
    await page.waitForTimeout(1000);

    // Verify Secure Browser UI
    const heading = page.locator('h2:has-text("PhishShield Secure Dedicated Browser")');
    assert(await heading.isVisible(), 'PhishShield Secure Dedicated Browser view rendered');

    // Verify Omnibar
    const omnibarInput = page.locator('input[placeholder*="Enter URL to inspect safely"]');
    assert(await omnibarInput.isVisible(), 'Security Omnibar address input is active');

    // Screenshot 2: Secure Browser initial view
    const screenshot2 = path.join(ARTIFACT_DIR, 'playwright_02_secure_browser_initial.png');
    await page.screenshot({ path: screenshot2 });
    console.log(`  📸 Saved screenshot: ${screenshot2}`);

    // Click PayPal Phish preset
    console.log('  Selecting "PayPal Phish (Critical)" preset...');
    const paypalPreset = page.locator('button:has-text("PayPal Phish (Critical)")');
    await paypalPreset.click();
    await page.waitForTimeout(500);

    const inputValue = await omnibarInput.inputValue();
    assert(inputValue.includes('paypal-verification'), `Omnibar input updated to: ${inputValue}`);

    // Submit evaluation
    console.log('  Triggering URL navigation and ML evaluation...');
    await omnibarInput.press('Enter');
    await page.waitForTimeout(2000);

    // Verify Adaptive Barrier Interstitial Screen
    const barrier = page.locator('text=PhishShield Adaptive Barrier Intercepted');
    assert(await barrier.isVisible(), 'Adaptive Warning Barrier triggered on phishing lure');

    const barrierScore = page.locator('text=/ 100');
    assert(await barrierScore.isVisible(), 'Threat score and CRITICAL indicator rendered on barrier');

    // Screenshot 3: Interstitial barrier
    const screenshot3 = path.join(ARTIFACT_DIR, 'playwright_03_barrier_screen.png');
    await page.screenshot({ path: screenshot3 });
    console.log(`  📸 Saved screenshot: ${screenshot3}`);

    // Test Sandbox delegation from barrier
    console.log('  Testing 1-click delegation to SDI Sandbox...');
    const sandboxBtn = page.locator('button:has-text("Open in Sandbox (SDI)")').first();
    assert(await sandboxBtn.isVisible(), 'Open in Sandbox (SDI) button is present');
    await sandboxBtn.click();
    await page.waitForTimeout(1500);

    // Verify Sandbox sessions view
    const sandboxHeading = page.locator('text=Sandbox Sessions').first();
    assert(await sandboxHeading.isVisible(), 'Navigated smoothly to Sandbox Sessions view');

    // Screenshot 4: Sandbox View
    const screenshot4 = path.join(ARTIFACT_DIR, 'playwright_04_sandbox_view.png');
    await page.screenshot({ path: screenshot4 });
    console.log(`  📸 Saved screenshot: ${screenshot4}`);

    // Navigate back to Secure Browser
    console.log('  Returning to Secure Browser view...');
    await browserNavBtn.click();
    await page.waitForTimeout(1000);

    // Test AI Security Analyst Report button
    console.log('  Testing "🤖 AI Report" button...');
    const aiReportBtn = page.locator('button:has-text("AI Report")').first();
    await aiReportBtn.click();
    await page.waitForTimeout(2000);

    // Verify AI Analyst Modal
    const modalHeading = page.locator('text=AI Security Analyst Report');
    assert(await modalHeading.isVisible(), 'AI Security Analyst Report modal displayed');

    // Screenshot 5: AI Report Modal
    const screenshot5 = path.join(ARTIFACT_DIR, 'playwright_05_ai_analyst_report.png');
    await page.screenshot({ path: screenshot5 });
    console.log(`  📸 Saved screenshot: ${screenshot5}`);

    // Close Modal
    const closeBtn = page.locator('button:has-text("Close")');
    if (await closeBtn.isVisible()) {
      await closeBtn.click();
      await page.waitForTimeout(500);
    }

    // Test Safe Navigation reset
    console.log('  Testing Return to Safety with Google preset...');
    const googlePreset = page.locator('button:has-text("Google (Safe)")');
    await googlePreset.click();
    await omnibarInput.press('Enter');
    await page.waitForTimeout(1500);

    const safePill = page.locator('text=LOW');
    assert(await safePill.isVisible(), 'Normal browsing permitted with LOW threat indicator');

    // Screenshot 6: Safe Navigation
    const screenshot6 = path.join(ARTIFACT_DIR, 'playwright_06_safe_navigation.png');
    await page.screenshot({ path: screenshot6 });
    console.log(`  📸 Saved screenshot: ${screenshot6}`);

  } catch (err) {
    assert(false, `Playwright UI execution error: ${err.message}`);
  } finally {
    if (browser) await browser.close();
  }

  console.log('\n===============================================================');
  console.log(`   TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('===============================================================\n');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTestSuite();
