/**
 * TrustVault Core Frontend Helpers
 * - CSRF token helper for fetch/AJAX
 * - Auto-dismiss notifications after 5s
 * - Upload file size check prior to submit
 */

document.addEventListener('DOMContentLoaded', () => {
    // Auto-dismiss alerts after 5 seconds if not error
    const alerts = document.querySelectorAll('.alert:not(.alert-danger):not(.alert-warning)');
    alerts.forEach((alert) => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 5000);
    });

    // Client-side file size safety check (supplementary to server-side enforcement)
    const fileInputs = document.querySelectorAll('input[type="file"][data-max-size]');
    fileInputs.forEach((input) => {
        input.addEventListener('change', () => {
            const maxBytes = parseInt(input.getAttribute('data-max-size'), 10);
            if (input.files.length > 0) {
                const file = input.files[0];
                if (file.size > maxBytes) {
                    const mb = (maxBytes / (1024 * 1024)).toFixed(0);
                    alert(`The selected file (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds the maximum allowed size of ${mb} MB.`);
                    input.value = '';
                }
            }
        });
    });
});

/**
 * Get CSRF cookie value for AJAX calls
 */
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
