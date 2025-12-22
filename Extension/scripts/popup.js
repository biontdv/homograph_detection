document.addEventListener('DOMContentLoaded', function() {
    const reportPhishingButton = document.getElementById('reportPhishing');
    const statusMessageDiv = document.getElementById('statusMessage');

    const toggleProtectionButton = document.getElementById('toggleProtection');
    const indicator = document.getElementById('indicator');
    const statusText = document.getElementById('statusText');

    // Load saved protection state 
    chrome.storage.sync.get(['tdv_enabled'], function(result) {
        let enabled = result.tdv_enabled || false;
        updateUI(enabled);

        // Toggle protection on button click 
        toggleProtectionButton.addEventListener('click', function() {
            enabled = !enabled;
            chrome.storage.sync.set({ 'tdv_enabled': enabled }, function() {
                console.log('Protection state updated:', enabled);
                updateUI(enabled);
            });
        });
    });

    // Report phishing 
    reportPhishingButton.addEventListener('click', function() {
        statusMessageDiv.textContent = 'Reporting...';
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            const currentUrl = tabs[0].url;
            console.log("Current URL to report:", currentUrl);

            chrome.runtime.sendMessage({ action: "sendUrlToBackend", url: currentUrl }, function(response) {
                if (response && response.success) {
                    statusMessageDiv.textContent = 'URL reported successfully!';
                } else {
                    statusMessageDiv.textContent = 'Failed to report URL.';
                    console.error('Error reporting URL:', response ? response.error : 'No response from background script');
                }
                setTimeout(() => statusMessageDiv.textContent = '', 3000);
            });
        });
    });

    // UI Update Helper
    function updateUI(enabled) {
        if (enabled) {
            indicator.classList.remove('off');
            indicator.classList.add('on');
            statusText.textContent = 'Enabled';
            toggleProtectionButton.textContent = 'Disable Protection';
            toggleProtectionButton.style.backgroundColor = '#ff3333';
        } else {
            indicator.classList.remove('on');
            indicator.classList.add('off');
            statusText.textContent = 'Disabled';
            toggleProtectionButton.textContent = 'Enable Protection';
            toggleProtectionButton.style.backgroundColor = '#1a73e8';
        }
    }
});
