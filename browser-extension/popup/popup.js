const urlElement = document.querySelector('#url')
const scanButton = document.querySelector('#scan')
const resultSection = document.querySelector('#result')
const errorElement = document.querySelector('#error')
let selectedUrl = ''

chrome.storage.session.get('pendingUrl').then(({ pendingUrl }) => {
  selectedUrl = pendingUrl || ''
  urlElement.textContent = selectedUrl || 'Choose a link on a page, then open this extension.'
})

scanButton.addEventListener('click', async () => {
  errorElement.hidden = true
  resultSection.hidden = true
  if (!selectedUrl) {
    showError('Select a link on a page before running an analysis.')
    return
  }
  scanButton.disabled = true
  scanButton.textContent = 'Analyzing…'
  try {
    const response = await fetch('http://127.0.0.1:8000/api/scan/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: selectedUrl }),
    })
    const data = await response.json()
    if (!response.ok) throw new Error(data.error || 'The scan request failed.')

    const verdict = document.querySelector('#verdict')
    verdict.className = `verdict ${data.verdict}`
    verdict.textContent = data.verdict === 'phishing' ? 'High risk · Phishing' :
      data.verdict === 'suspicious' ? 'Suspicious · Review first' : 'No strong URL warning signs'
    document.querySelector('#score').textContent = `${data.risk_score}% risk · ${data.analysis_mode === 'hybrid' ? 'Model + rules' : 'Rule-based'}`
    const reasons = document.querySelector('#reasons')
    reasons.replaceChildren(...data.reasons.slice(0, 3).map((reason) => {
      const item = document.createElement('li')
      item.textContent = reason
      return item
    }))
    document.querySelector('#open').hidden = false
    resultSection.hidden = false
  } catch (error) {
    showError(`${error.message} Check that the local SignalGuard API is running.`)
  } finally {
    scanButton.disabled = false
    scanButton.textContent = 'Analyze link'
  }
})

document.querySelector('#open').addEventListener('click', () => {
  if (!selectedUrl) return
  chrome.tabs.create({ url: selectedUrl })
  window.close()
})

function showError(message) {
  errorElement.textContent = message
  errorElement.hidden = false
}