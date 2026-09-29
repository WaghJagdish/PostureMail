import { test, expect } from "@playwright/test";

test.describe("Analyst Triage & Forensic Inspection Workflow", () => {
  test("complete triage loop: overview -> filter critical -> inspect STARTTLS FSM & evidence hex -> submit verdict", async ({
    page,
  }) => {
    // 1. Load the analyst frontend console
    await page.goto("http://localhost:5173");

    // 2. Assert Header & Ingestion status
    await expect(page.locator("text=PECFF FORENSICS CONSOLE")).toBeVisible();
    await expect(page.locator("text=enterprise_perimeter_core_mail_1000.pcap")).toBeVisible();

    // 3. Navigate to Overview (VIEW 2)
    await page.click("button:has-text('Analysis Overview')");
    await expect(page.locator("text=Risk Distribution (Click to Filter)")).toBeVisible();
    await expect(page.locator("text=STARTTLS Upgrade Health per Destination MX")).toBeVisible();

    // 4. Click on Critical risk band in the Donut legend to filter sessions
    await page.click("[title='Filter table to CRITICAL']");

    // 5. Verify Session Table (VIEW 3) is filtered to CRITICAL flows
    await expect(page.locator("button:has-text('Critical Risk')")).toBeVisible();
    const firstRow = page.locator("text=sess-0001").first();
    await expect(firstRow).toBeVisible();

    // 6. Click session row to open Session Detail (VIEW 4)
    await firstRow.click();
    await expect(page.locator("text=STARTTLS Finite State Machine Timeline")).toBeVisible();
    await expect(page.locator("text=NIST SP 800-57 Risk Score Breakdown")).toBeVisible();

    // 7. Verify FSM Timeline and click a node to reveal Byte Evidence Hex
    const fsmNode = page.locator("text=S_STRIP_DETECTED").first();
    if (await fsmNode.isVisible()) {
      await fsmNode.click();
    }
    await expect(page.locator("text=Stream Offset:")).toBeVisible();
    await expect(page.locator("pre.font-mono")).toBeVisible();

    // 8. Submit Analyst Ground Truth Verdict
    await page.click("button:has-text('Submit & Record Verdict')");
    await expect(page.locator("text=Analyst Verdict Recorded")).toBeVisible();

    // 9. Navigate to Correlations (VIEW 5) and verify Beaconing Scatter
    await page.click("button:has-text('Corpus Correlations')");
    await expect(page.locator("text=Beaconing & Periodicity Analysis")).toBeVisible();
  });
});
