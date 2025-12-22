
// Menggunakan Set untuk menyimpan domain yang diizinkan untuk dilewati
const allowedDomains = new Set();

// --- Mencegat Navigasi SEBELUM Dimulai ---
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Pastikan ini adalah frame utama (bukan iframe) dan bukan URL internal Chrome
    if (details.frameId === 0 && details.url && !details.url.startsWith("chrome://")) {
        console.log(`Navigasi dimulai pada tab ${details.tabId}. Mengirim URL: ${details.url}`);

        // PENTING: Periksa apakah domain ada di daftar pengecualian
        const hostname = new URL(details.url).hostname;
        if (allowedDomains.has(hostname)) {
            console.log(`[BYPASS] Mengizinkan navigasi untuk domain ${hostname}`);
            return; // Hentikan eksekusi, biarkan navigasi berhasil
        }

        const result = await sendUrlToBackend(details.url);

        if (result.success && result.data.status === "danger") {
          
            const encodedMessage = encodeURIComponent(result.data.message);
            const encodedOriginalUrl = encodeURIComponent(details.url);
            const redirectUrl = chrome.runtime.getURL(`landing.html?message=${encodedMessage}&originalUrl=${encodedOriginalUrl}`);

            // Segera update URL tab sebelum halaman berbahaya dimuat
            chrome.tabs.update(details.tabId, { url: redirectUrl });
        }
    }
}, { url: [{ schemes: ["http", "https"] }] });

// --- Menerima Perintah dari Skrip Lain (misalnya dari popup atau landing page) ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Logika untuk mengirim URL secara manual dari popup
    if (request.action === "sendUrlToBackend") {
        sendUrlToBackend(request.url)
            .then(response => sendResponse(response))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true; 
    }
    
    // Logika untuk melanjutkan ke URL yang diblokir
    if (request.action === "continueToPhish") {
        const urlToContinue = request.url;
        try {
            const hostname = new URL(urlToContinue).hostname;
            allowedDomains.add(hostname); // Tambahkan domain ke daftar pengecualian
            console.log(`[CONTINUE] Domain ${hostname} ditambahkan ke daftar izin.`);

            chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
                if (tabs && tabs.length > 0) {
                    // Arahkan tab kembali ke URL asli yang berbahaya
                    chrome.tabs.update(tabs[0].id, { url: urlToContinue });
                }
            });
        } catch (e) {
            console.error('Invalid URL received for "continueToPhish" action:', e);
        }
    }
});


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // ... (Logika yang ada: sendUrlToBackend, continueToPhish) ...

    if (request.action === "dangerDetected") {
        // Ambil ID tab dari sender
        const tabId = sender.tab.id;
        const originalUrl = request.url;
        const reason = request.reason;

        console.log(`[CONTENT SCRIPT] Ancaman terdeteksi di tab ${tabId}: ${reason}`);

        // Periksa apakah URL sudah diizinkan untuk melewati deteksi
        const hostname = new URL(originalUrl).hostname;
        if (allowedDomains.has(hostname)) {
            console.log(`[BYPASS - CONTENT] Mengizinkan navigasi untuk domain ${hostname}`);
            return;
        }

        // Redirect pengguna ke halaman peringatan
        const encodedMessage = encodeURIComponent(reason);
        const encodedOriginalUrl = encodeURIComponent(originalUrl);
        const redirectUrl = chrome.runtime.getURL(`landing.html?message=${encodedMessage}&originalUrl=${encodedOriginalUrl}`);

        chrome.tabs.update(tabId, { url: redirectUrl });
    }
});
