(async function() {

    // START: Pengukuran Waktu Eksekusi Content Script
    const contentScriptStartTime = performance.now();

 
    if (window.location.href.startsWith("chrome-extension://") || window.location.href === "about:blank") {
        return;
    }

    // Periksa mode deteksi dari storage
    let detectionMode = 'basic';
    try {
        const result = await chrome.storage.sync.get({ detectionMode: 'basic' });
        detectionMode = result.detectionMode;
    } catch (error) {
        console.error("Gagal mengambil mode deteksi:", error);
        return;
    }

    // Hanya jalankan jika mode aggressive
    if (detectionMode !== 'aggressive') {
        console.log("Mode basic - Content script tidak dijalankan");
        return;
    }

    /**
     * Mengirim pesan bahaya ke background script.
     * @param {string} reason - Alasan kenapa halaman dianggap berbahaya.
     * @param {string} originalUrl - URL halaman yang terdeteksi.
     */
    function sendDangerMessage(reason, originalUrl) {
        console.warn(`[DETEKSI - Aggressive] Alasan: ${reason} | URL: ${originalUrl}`);
        chrome.runtime.sendMessage({
            action: "dangerDetected",
            reason: reason,
            url: originalUrl
        });
    }

    // --- 1. Pengecekan Clickjacking (Prioritas Utama) ---
    try {
        if (window.self !== window.top) {
            let topUrl = '';
            try {
                topUrl = window.top.location.href;
            } catch (e) {
                topUrl = 'Different Origin - Cannot Access';
            }
            sendDangerMessage(
                `Halaman ini dimuat di dalam frame dari situs lain (${topUrl}), kemungkinan serangan Clickjacking.`,
                window.location.href
            );
            return;
        } else {
            console.log("Halaman adalah top frame - aman dari clickjacking");
        }
    } catch (error) {
        console.error("Error dalam deteksi clickjacking:", error);
    }

    console.log("Mode Aggressive: Lolos cek clickjacking, melanjutkan analisis konten...");

    // --- 2. Pengecekan Lainnya ---
    const hostname = window.location.hostname;

    let inWhitelist = false;
    try {
        const response = await chrome.runtime.sendMessage({ action: "checkWhitelist", domain: hostname });
        if (response) {
            inWhitelist = response.is_whitelisted;
        }
    } catch (err) {
        console.error("Gagal mengecek whitelist dari background script:", err.message);
    }

    if (!inWhitelist) {
        // --- Deteksi Formulir Phishing ---
        const suspiciousInputs = [
            "username", "user", "userid", "password", "pin", "saldo", "rekening",
            "login", "email", "pass", "account", "balance"
        ];
        let hasSuspiciousForm = false;
        document.querySelectorAll("form input").forEach(input => {
            const combined = [
                input.name, input.id, input.placeholder, input.getAttribute("aria-label")
            ].map(x => (x || "").toLowerCase()).join(" ");

            if (suspiciousInputs.some(word => combined.includes(word)) || (input.type || "").toLowerCase() === "password") {
                hasSuspiciousForm = true;
            }
        });

        if (hasSuspiciousForm && window.location.protocol !== "https:") {
            console.log("Formulir mencurigakan di non-HTTPS terdeteksi. Mengecek whitelist backend...");

            // 1. Kirim pesan ke background untuk cek whitelist backend
            const backendStatus = await chrome.runtime.sendMessage({
                action: "checkBackendWhitelist",
                domain: hostname
            });

            // 2. Ambil hasilnya (default ke false jika ada masalah)
            const isBackendWhitelisted = backendStatus ? backendStatus.is_whitelisted : false;

            // 3. Terapkan logika baru
            if (!isBackendWhitelisted) {
                sendDangerMessage(
                    "Formulir login/sensitif terdeteksi di domain non-HTTPS yang tidak ada di whitelist.",
                    window.location.href
                );
            } else {
                console.log("Domain ada di whitelist backend, formulir non-HTTPS diizinkan.");
            }
        }
        // --- Deteksi Meta Refresh ---
        if (document.querySelector('meta[http-equiv="refresh"]')) {
            sendDangerMessage("Halaman ini menggunakan meta refresh untuk pengalihan otomatis yang mencurigakan.", window.location.href);
        }
        
        // --- Intersepsi Pengalihan via JavaScript ---
        const originalAssign = window.location.assign.bind(window.location);
        window.location.assign = function(url) {
            sendDangerMessage(`Terdeteksi upaya pengalihan JavaScript ke: ${url}`, window.location.href);
            return originalAssign(url);
        };

        const originalReplace = window.location.replace.bind(window.location);
        window.location.replace = function(url) {
            sendDangerMessage(`Terdeteksi upaya pengalihan JavaScript ke: ${url}`, window.location.href);
            return originalReplace(url);
        };


        // MULAI: Deteksi Keylogger dan Perilaku Mencurigakan ---
  
        // Daftar event keyboard yang sering disalahgunakan
        const SUSPICIOUS_KEY_EVENTS = ['keydown', 'keyup', 'keypress'];

        // 1. Memantau `addEventListener` untuk mendeteksi pendaftaran listener berbahaya
        const originalAddEventListener = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            try {
                const elementType = this.tagName ? this.tagName.toLowerCase() : 'window/document';
                const listenerCode = listener.toString();

                // Deteksi untuk Test #3: Event listener keyboard global pada document atau window
                if ((this === document || this === window) && SUSPICIOUS_KEY_EVENTS.includes(type)) {
                    sendDangerMessage(
                        `Waspada! Listener keyboard global (${type}) terdeteksi, berpotensi merekam semua ketikan Anda.`,
                        window.location.href
                    );
                }

                // Deteksi untuk Test #2: Form Hijacking
                if (elementType === 'form' && type === 'submit') {
                    if (listenerCode.includes('preventDefault')) {
                        sendDangerMessage(
                            'Waspada! Potensi Form Hijacking. Pengiriman data formulir standar dibatalkan oleh skrip.',
                            window.location.href
                        );
                    }
                }

            // Deteksi untuk Test #1 (Heuristik): Cek listener pada input
            if ((elementType === 'input' || elementType === 'textarea') && SUSPICIOUS_KEY_EVENTS.includes(type)) {
                // Ditambahkan .send( untuk menangkap WebSocket.send() dan XHR.send()
                if (listenerCode.includes('fetch(') || listenerCode.includes('XMLHttpRequest') || listenerCode.includes('.src =') || listenerCode.includes('.send(')) {
                    sendDangerMessage(
                        `Waspada! Keylogger terdeteksi pada kolom input. Skrip mencoba mengirim data ketikan Anda.`,
                        window.location.href
                    );
                }
            }
            } catch (e) {
                // Abaikan error jika terjadi
            }

            // Panggil fungsi asli agar fungsionalitas halaman tidak rusak
            return originalAddEventListener.call(this, type, listener, options);
        };

        // 2. Memantau koneksi WebSocket
        const OriginalWebSocket = window.WebSocket;
        window.WebSocket = new Proxy(OriginalWebSocket, {
            construct(target, args) {
                const url = args[0];
                try {
                    const wsHostname = new URL(url).hostname;
                    // Deteksi untuk Test #5: Koneksi WebSocket ke domain yang berbeda
                    if (wsHostname !== window.location.hostname) {
                        sendDangerMessage(
                            `Waspada! Terdeteksi koneksi WebSocket ke server eksternal (${wsHostname}) yang dapat mencuri data.`,
                            window.location.href
                        );
                    }
                } catch (e) {
                    // URL mungkin relatif atau tidak valid, abaikan.
                }
                
                // Buat instance WebSocket asli
                return new target(...args);
            }
        });

        // 3. Pindai dan pantau iFrame tersembunyi
        function detectHiddenIframes() {
            document.querySelectorAll('iframe').forEach(iframe => {
                const style = window.getComputedStyle(iframe);
                if (style.display === 'none' || style.visibility === 'hidden' || iframe.width === '0' || iframe.height === '0') {
                    // Deteksi untuk Test #4: iFrame tersembunyi
                    sendDangerMessage(
                        `Waspada! iFrame tersembunyi terdeteksi, berpotensi digunakan untuk mencuri data (src: ${iframe.src}).`,
                        window.location.href
                    );
                }
            });
        }

        // Jalankan deteksi saat halaman dimuat
        detectHiddenIframes();

        // Gunakan MutationObserver untuk mendeteksi iframe yang ditambahkan secara dinamis
        const observer = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.tagName === 'IFRAME') {
                        setTimeout(() => { // Beri sedikit waktu agar style diterapkan
                            const style = window.getComputedStyle(node);
                             if (style.display === 'none' || style.visibility === 'hidden' || node.width === '0' || node.height === '0') {
                                sendDangerMessage(
                                    `Waspada! iFrame tersembunyi baru saja ditambahkan ke halaman.`,
                                    window.location.href
                                );
                            }
                        }, 100);
                    }
                });
            });
        });

        // Mulai mengamati perubahan pada seluruh dokumen
        if (document.body) {
            observer.observe(document.body, { childList: true, subtree: true });
        } else {
            window.addEventListener('DOMContentLoaded', () => {
                 observer.observe(document.body, { childList: true, subtree: true });
            });
        }

    } // Akhir dari if (!inWhitelist)

    // END: Pengukuran Waktu Eksekusi Content Script
    const contentScriptEndTime = performance.now();
    const duration = contentScriptEndTime - contentScriptStartTime;
    console.log(`⏱️ [CONTENT SCRIPT] Total waktu inisialisasi & analisis awal: ${duration.toFixed(2)} ms`);

    // START: Pengukuran Memori
    if (performance.memory) {
        const memoryInfo = performance.memory;
        const usedJSHeapSizeMB = (memoryInfo.usedJSHeapSize / 1024 / 1024).toFixed(2);
        console.log(`🧠 [CONTENT SCRIPT] Penggunaan Memori JS Heap setelah analisis: ${usedJSHeapSizeMB} MB`);
    }
    // END: Pengukuran Memori

    

})();