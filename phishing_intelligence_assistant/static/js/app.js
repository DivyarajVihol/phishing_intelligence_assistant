// Phishing Intelligence Assistant client script
document.addEventListener("DOMContentLoaded", () => {
  const submitForm = document.getElementById("submit-form");
  const submitBtn = document.getElementById("submit-btn");
  if (submitForm && submitBtn) {
    submitForm.addEventListener("submit", () => {
      submitBtn.setAttribute("disabled", "disabled");
      submitBtn.textContent = "Analysing...";
    });
  }

  const copyBtn = document.getElementById("copy-defanged-btn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const urlToCopy = copyBtn.getAttribute("data-url");
      if (urlToCopy && navigator.clipboard) {
        navigator.clipboard.writeText(urlToCopy).then(() => {
          const originalText = copyBtn.textContent;
          copyBtn.textContent = "Copied!";
          setTimeout(() => {
            copyBtn.textContent = originalText;
          }, 2000);
        });
      }
    });
  }
});
