// Ambil pesan dan URL asli dari parameter URL
const urlParams = new URLSearchParams(window.location.search);
const message = urlParams.get('message');
const originalUrl = urlParams.get('originalUrl');
const continueBtn = document.getElementById('continueBtn');

if (message) {
  // Decode pesan dan ubah teks elemen <p>
  document.getElementById('message').innerText = decodeURIComponent(message);
}

// Handle tombol 'continue' untuk melanjutkan ke halaman berbahaya
continueBtn.addEventListener('click', () => {
  // Mengirim pesan ke skrip latar belakang untuk melanjutkan ke URL asli
  chrome.runtime.sendMessage({ 
    action: "continueToPhish",
    url: decodeURIComponent(originalUrl) 
  });
});