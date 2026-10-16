chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'signalguard-scan-link',
    title: 'Check link with SignalGuard',
    contexts: ['link'],
  })
})

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== 'signalguard-scan-link' || !info.linkUrl) return
  chrome.storage.session.set({ pendingUrl: info.linkUrl })
  chrome.action.openPopup()
})