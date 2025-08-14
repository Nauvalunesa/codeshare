// Lunox.io Clone - Main JavaScript

// Rich Text Editor Functions
function formatText(command, value = null) {
  document.execCommand(command, false, value)
  document.getElementById("content").focus()
}

function insertCodeBlock() {
  const selection = window.getSelection()
  const range = selection.getRangeAt(0)

  const codeBlock = document.createElement("pre")
  codeBlock.innerHTML = "<code>// Your code here</code>"
  codeBlock.style.background = "#1e293b"
  codeBlock.style.padding = "1rem"
  codeBlock.style.borderRadius = "0.5rem"
  codeBlock.style.fontFamily = "JetBrains Mono, monospace"

  range.insertNode(codeBlock)
  selection.removeAllRanges()
}

// Copy to Clipboard
function copyToClipboard(text) {
  navigator.clipboard
    .writeText(text)
    .then(() => {
      showNotification("Copied to clipboard!", "success")
    })
    .catch(() => {
      showNotification("Failed to copy", "error")
    })
}

// Show Notifications
function showNotification(message, type = "info") {
  const notification = document.createElement("div")
  notification.className = `notification notification-${type}`
  notification.textContent = message

  notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        color: white;
        font-weight: 500;
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `

  if (type === "success") {
    notification.style.background = "#10b981"
  } else if (type === "error") {
    notification.style.background = "#ef4444"
  } else {
    notification.style.background = "#6366f1"
  }

  document.body.appendChild(notification)

  setTimeout(() => {
    notification.style.animation = "slideOut 0.3s ease"
    setTimeout(() => {
      document.body.removeChild(notification)
    }, 300)
  }, 3000)
}

// Form Validation
function validateForm(formId) {
  const form = document.getElementById(formId)
  const inputs = form.querySelectorAll("input[required], textarea[required]")
  let isValid = true

  inputs.forEach((input) => {
    if (!input.value.trim()) {
      input.style.borderColor = "#ef4444"
      isValid = false
    } else {
      input.style.borderColor = "#334155"
    }
  })

  return isValid
}

// Password Strength Checker
function checkPasswordStrength(password) {
  let strength = 0
  const checks = [
    /.{8,}/, // At least 8 characters
    /[a-z]/, // Lowercase
    /[A-Z]/, // Uppercase
    /[0-9]/, // Numbers
    /[^A-Za-z0-9]/, // Special characters
  ]

  checks.forEach((check) => {
    if (check.test(password)) strength++
  })

  return strength
}

// Auto-save functionality
let autoSaveTimer
function enableAutoSave(textareaId) {
  const textarea = document.getElementById(textareaId)
  if (!textarea) return

  textarea.addEventListener("input", () => {
    clearTimeout(autoSaveTimer)
    autoSaveTimer = setTimeout(() => {
      const content = textarea.value
      localStorage.setItem("autosave_" + textareaId, content)
      showNotification("Auto-saved", "info")
    }, 2000)
  })

  // Load auto-saved content
  const saved = localStorage.getItem("autosave_" + textareaId)
  if (saved && !textarea.value) {
    textarea.value = saved
  }
}

// Syntax highlighting for code blocks
function highlightCode() {
  const codeBlocks = document.querySelectorAll("pre code")
  codeBlocks.forEach((block) => {
    // Simple syntax highlighting
    let html = block.innerHTML

    // Keywords
    html = html.replace(
      /\b(function|var|let|const|if|else|for|while|return|class|import|export)\b/g,
      '<span style="color: #6366f1;">$1</span>',
    )

    // Strings
    html = html.replace(/(["'])((?:\\.|(?!\1)[^\\])*?)\1/g, '<span style="color: #10b981;">$1$2$1</span>')

    // Comments
    html = html.replace(/(\/\/.*$|\/\*[\s\S]*?\*\/)/gm, '<span style="color: #cbd5e1;">$1</span>')

    block.innerHTML = html
  })
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  // Enable auto-save for content textarea
  enableAutoSave("content")

  // Highlight existing code blocks
  highlightCode()

  // Add copy buttons to code blocks
  const codeBlocks = document.querySelectorAll("pre")
  codeBlocks.forEach((block) => {
    const copyBtn = document.createElement("button")
    copyBtn.textContent = "Copy"
    copyBtn.className = "btn btn-secondary"
    copyBtn.style.cssText =
      "position: absolute; top: 0.5rem; right: 0.5rem; font-size: 0.75rem; padding: 0.25rem 0.5rem;"

    block.style.position = "relative"
    block.appendChild(copyBtn)

    copyBtn.addEventListener("click", () => {
      const code = block.querySelector("code")
      copyToClipboard(code.textContent)
    })
  })
})

// Add CSS animations
const style = document.createElement("style")
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`
document.head.appendChild(style)
