// ─────────────────────────────────────────────
//  ScamShield — background.js  (MV3 service worker)
// ─────────────────────────────────────────────

// Clear badge when a tab navigates to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  }
});

// Message handler
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "SET_BADGE") {
    const colors = {
      LOW:    [34, 197, 94,  255],
      MEDIUM: [245,158, 11,  255],
      HIGH:   [239, 68, 68,  255],
    };
    const labels = { LOW: "✓", MEDIUM: "!", HIGH: "!!" };
    const risk = msg.risk || "LOW";
    chrome.action.setBadgeBackgroundColor({ tabId: msg.tabId, color: colors[risk] || colors.LOW }).catch(()=>{});
    chrome.action.setBadgeText({ tabId: msg.tabId, text: labels[risk] || "" }).catch(()=>{});
    sendResponse({ ok: true });
  }
  return true;
});