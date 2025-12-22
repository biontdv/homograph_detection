// Menggunakan Set untuk menyimpan domain yang diizinkan untuk dilewati
const allowedDomains = new Set();

// --- Fungsi untuk mengirim URL ke Flask backend (dengan PENGUKURAN KINERJA) ---
async function sendUrlToBackend(url) {
    const backendUrl = 'http://127.0.0.1:5000/sendurl';
    
    // Waktu #1: Tepat sebelum request dikirim
    const startTime = performance.now();

    try {
        const response = await fetch(backendUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        // Waktu #4: Tepat setelah response dari backend diterima
        const endTime = performance.now();

        if (response.ok) {
            const data = await response.json();
            console.log('Backend response (Heuristic):', data);

            // --- KALKULASI PENGUKURAN ---
            const totalDuration = endTime - startTime;
            // Ambil durasi dari backend, jika tidak ada, anggap 0
            const backendDetectionDuration = data.detection_duration_ms || 0;
            const networkDuration = totalDuration - backendDetectionDuration;
            
            // TAMPILKAN HASIL PENGUKURAN DI CONSOLE
            console.log("--- ⏱️ Hasil Pengukuran Kecepatan Backend ---");
            console.table({
              'Durasi Total (Ekstensi ➔ Backend ➔ Ekstensi)': `${totalDuration.toFixed(2)} ms`,
              '1. Durasi Proses Backend': `${backendDetectionDuration.toFixed(2)} ms`,
              '2. Durasi Jaringan (Pergi-Pulang)': `${networkDuration.toFixed(2)} ms`,
            });

            // Kembalikan data seperti semula agar fungsi lain tidak terganggu
            return { success: true, data: data };

        } else {
            const errorText = await response.text();
            console.error('Backend error response (Heuristic):', response.status, errorText);
            return { success: false, error: `Backend responded with status ${response.status}: ${errorText}` };
        }
    } catch (error) {
        console.error('Error sending URL to backend (Heuristic):', error);
        return { success: false, error: error.message };
    }
}

// --- Fungsi Utama untuk Analisis & Blokir (Mode Basic) ---
// --- TIDAK ADA PERUBAHAN DI FUNGSI INI ---
export async function analyzeAndBlockUrlHeuristically(details) {
    if (details.frameId !== 0 || !details.url || details.url.startsWith("chrome://")) {
        return;
    }

    console.log(`Mode Basic: Menganalisis navigasi ke: ${details.url}`);

    const hostname = new URL(details.url).hostname;
    if (allowedDomains.has(hostname)) {
        console.log(`[BYPASS] Mengizinkan navigasi untuk domain ${hostname} yang ada di daftar putih.`);
        return;
    }

    const result = await sendUrlToBackend(details.url);

    if (result.success && result.data.status === "danger") {
        console.log(`[BLOKIR - Heuristic] URL terdeteksi berbahaya: ${details.url}`);
        const encodedMessage = encodeURIComponent(result.data.message);
        const encodedOriginalUrl = encodeURIComponent(details.url);
        const redirectUrl = chrome.runtime.getURL(`landing.html?message=${encodedMessage}&originalUrl=${encodedOriginalUrl}`);
        
        chrome.tabs.update(details.tabId, { url: redirectUrl });
    }
}

// Ekspor juga allowedDomains agar bisa diakses dari background.js jika diperlukan
export { allowedDomains };