import { analyzeAndBlockUrlHeuristically, allowedDomains } from './heuristic.js';


const blockedTabIds = new Set();

// --- Fungsi untuk memblokir halaman berdasarkan deteksi
async function blockPage(tabId, reason, originalUrl) {
    if (blockedTabIds.has(tabId)) return;

    console.log(`[BLOKIR] Memblokir Tab ${tabId}. Alasan: ${reason}`);
    blockedTabIds.add(tabId); 
    const encodedMessage = encodeURIComponent(reason);
    const encodedOriginalUrl = encodeURIComponent(originalUrl);
    const redirectUrl = chrome.runtime.getURL(`landing.html?message=${encodedMessage}&originalUrl=${encodedOriginalUrl}`);
    
    chrome.tabs.update(tabId, { url: redirectUrl });
}



async function navigationController(details) {
    // Hanya proses frame utama (frameId === 0)
    if (details.frameId !== 0 || !details.url || details.url.startsWith("chrome://")) {
        return;
    }

    // START: Pengukuran Waktu
    const startTime = performance.now();

    blockedTabIds.delete(details.tabId);

    const hostname = new URL(details.url).hostname;
    if (allowedDomains.has(hostname)) {
        console.log(`[BYPASS] Domain ${hostname} sudah diizinkan. Melewati semua analisis.`);
        return;
    }

    
    await new Promise(resolve => {
        chrome.storage.sync.get({ detectionMode: 'basic' }, (result) => {
            const mode = result.detectionMode;
            console.log(`Navigasi ke ${details.url}, Mode Aktif: ${mode}`);

            if (mode === 'aggressive') {
                console.log("Mode Aggressive: Menyuntikkan content script ke semua frame.");
                chrome.scripting.executeScript({
                    target: { 
                        tabId: details.tabId,
                        allFrames: true
                    },
                    files: ['scripts/content.js'],
                }).catch(err => console.error("Gagal inject content script:", err));
            }

            console.log("Menjalankan analisis heuristic (berbasis URL).");
        
            analyzeAndBlockUrlHeuristically(details).then(resolve);
        });
    });
    
    // END: Pengukuran Waktu
    const endTime = performance.now();
    const duration = endTime - startTime;
    console.log(`⏱️ [BACKGROUND] Total waktu analisis navigasi untuk ${details.url}: ${duration.toFixed(2)} ms`);



}



// --- Listeners Navigasi ---
chrome.webNavigation.onCommitted.addListener(navigationController, {
    url: [{ schemes: ["http", "https"] }] // <-- PERBAIKAN TYPO DI SINI
});
chrome.webNavigation.onErrorOccurred.addListener(navigationController, {
    url: [{ schemes: ["http", "https"] }] // <-- DAN DI SINI
});

async function measureAndLogMemory(contextMessage = "Pengukuran Memori") {

    // Cek apakah API 'processes' ada di dalam objek 'chrome'
    if (!chrome.processes) {
        console.error(`❌ [INVESTIGASI] API 'chrome.processes' TIDAK TERSEDIA saat ini.`);
        // Tampilkan semua API yang tersedia untuk melihat apa saja yang ada
        console.log("API yang tersedia di 'chrome':", Object.keys(chrome));
        return; // Hentikan eksekusi karena API tidak ada
    }


    try {
        const extensionProcesses = await chrome.processes.getProcessInfo([], true);
        const serviceWorkerProcess = Object.values(extensionProcesses).find(p => p.type === 'service_worker');

        if (serviceWorkerProcess) {
            const memoryUsageMB = (serviceWorkerProcess.privateMemory / 1024 / 1024).toFixed(2);
            console.log(`🧠 [BACKGROUND] ${contextMessage}: ${memoryUsageMB} MB`);
        } else {
            console.log(`🧠 [BACKGROUND] ${contextMessage}: Tidak dapat menemukan proses service worker.`);
        }
    } catch (error) {
        console.error(`🧠 [BACKGROUND] ${contextMessage}: Gagal mendapatkan info memori.`, error);
    }
}


// --- Listener untuk Menerima Pesan dari Skrip Lain ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "dangerDetected") {
        if (sender.tab && sender.tab.id) {
            if (blockedTabIds.has(sender.tab.id)) {
                console.log(`Mengabaikan pesan bahaya duplikat untuk Tab ${sender.tab.id}`);
                return;
            }
            setTimeout(() => measureAndLogMemory("Pengukuran sebelum blokir"), 0);
            blockPage(sender.tab.id, request.reason, request.url);
        }
        // Tidak perlu 'return true' karena tidak ada sendResponse
        return; 
    }
        if (request.action === "checkBackendWhitelist") {
      
        (async () => {
            try {
                const response = await fetch('http://127.0.0.1:5000/domainchecker', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: request.domain })
                });

                if (!response.ok) {
                    console.error(`Backend /domainchecker error: Status ${response.status}`);
                    sendResponse({ is_whitelisted: false }); // Anggap tidak whitelisted jika error
                    return;
                }

                const data = await response.json();
                console.log(`[BACKEND WHITELIST] Respon untuk ${request.domain}:`, data);
                // Pastikan mengirim kembali boolean murni
                sendResponse({ is_whitelisted: data.is_whitelisted === true });

            } catch (e) {
                console.error("Gagal menghubungi backend untuk cek whitelist:", e);
                sendResponse({ is_whitelisted: false }); // Anggap tidak whitelisted jika gagal konek
            }
        })();
        
        return true; // WAJIB: Menjaga port pesan tetap terbuka untuk respons asinkron
    }
    
  

    // Permintaan dari popup untuk analisis manual
    if (request.action === "sendUrlToBackend") {
        import('./heuristic.js').then(module => {
            // Menggunakan sendUrlToBackend dari heuristic.js
            module.sendUrlToBackend(request.url).then(sendResponse);
        });
        return true; // Penting untuk menjaga channel pesan tetap terbuka untuk response
    }
    
    // Permintaan dari landing page untuk melanjutkan
    if (request.action === "continueToPhish") {
        try {
            const urlToContinue = new URL(request.url);
            allowedDomains.add(urlToContinue.hostname);
            console.log(`[CONTINUE] Domain ${urlToContinue.hostname} ditambahkan ke daftar izin.`);
            // Pastikan menggunakan tab.id dari pengirim pesan (halaman landing)
            if (sender.tab && sender.tab.id) {
                chrome.tabs.update(sender.tab.id, { url: request.url });
            }
        } catch (e) {
            console.error('Invalid URL for "continueToPhish":', e);
        }
        // Tidak perlu 'return true'
        return; 
    }
    
    // Permintaan dari content.js untuk cek whitelist
    if (request.action === "checkWhitelist") {
        // Logika ini mungkin tidak lagi digunakan karena cek whitelist sudah ada di awal navigationController,
        // namun tetap disediakan jika diperlukan.
        const isWhitelisted = allowedDomains.has(request.domain);
        sendResponse({ is_whitelisted: isWhitelisted });
        // Tidak perlu 'return true' karena response-nya sinkron
        return; 
    }
});

// Hapus tab dari set saat ditutup
chrome.tabs.onRemoved.addListener((tabId) => {
    blockedTabIds.delete(tabId);
});