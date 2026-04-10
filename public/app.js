const state = {
  token: localStorage.getItem('cuts_token') || '',
  user: JSON.parse(localStorage.getItem('cuts_user') || 'null')
}

const toast = document.getElementById('toast')

function showToast(message, isError = false) {
  if (!toast) return
  toast.textContent = message
  toast.style.background = isError ? 'rgba(126, 34, 34, 0.94)' : 'rgba(26, 22, 18, 0.92)'
  toast.classList.add('visible')
  window.clearTimeout(showToast.timer)
  showToast.timer = window.setTimeout(() => {
    toast.classList.remove('visible')
  }, 2600)
}

async function apiFetch(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  }

  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`
  }

  const response = await fetch(path, { ...options, headers })
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(data.error || 'Request failed')
  }

  return data
}

function saveSession(token, user) {
  state.token = token
  state.user = user
  localStorage.setItem('cuts_token', token)
  localStorage.setItem('cuts_user', JSON.stringify(user))
}

function clearSession() {
  state.token = ''
  state.user = null
  localStorage.removeItem('cuts_token')
  localStorage.removeItem('cuts_user')
}

function setSessionUI() {
  const sessionCard = document.getElementById('sessionCard')
  const sessionUser = document.getElementById('sessionUser')
  const authToggle = document.getElementById('authToggle')
  const authPanel = document.getElementById('authPanel')

  if (!sessionCard || !sessionUser || !authToggle || !authPanel) return

  if (state.user) {
    sessionUser.textContent = `${state.user.username} (${state.user.email})`
    sessionCard.hidden = false
    authToggle.textContent = 'Dashboard'
  } else {
    sessionCard.hidden = true
    authToggle.textContent = 'Sign in'
  }

  authToggle.onclick = () => {
    authPanel.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
}

function bindTabs() {
  const buttons = document.querySelectorAll('[data-tab-target]')
  const panels = document.querySelectorAll('[data-tab-panel]')
  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      const target = button.dataset.tabTarget
      buttons.forEach((entry) => entry.classList.toggle('active', entry === button))
      panels.forEach((panel) => panel.classList.toggle('active', panel.dataset.tabPanel === target))
    })
  })
}

function formatDate(value) {
  if (!value) return 'Unknown'
  return new Date(value).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })
}

function renderUrls(urls, isAuthenticated = true) {
  const body = document.getElementById('urlsTableBody')
  const metricLinks = document.getElementById('metricLinks')
  const metricClicks = document.getElementById('metricClicks')
  const metricProtected = document.getElementById('metricProtected')

  if (!body) return

  if (!urls.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty-state">${
      isAuthenticated ? 'No links yet. Create your first one above.' : 'Log in to see your links here.'
    }</td></tr>`
  } else {
    body.innerHTML = urls.map((url) => `
      <tr>
        <td><strong>${url.shortCode}</strong></td>
        <td><a href="${url.originalUrl}" target="_blank" rel="noreferrer">${url.originalUrl}</a></td>
        <td>${url.clicks || 0}</td>
        <td>${formatDate(url.expiresAt)}</td>
      </tr>
    `).join('')
  }

  if (metricLinks) metricLinks.textContent = String(urls.length)
  if (metricClicks) metricClicks.textContent = String(urls.reduce((sum, item) => sum + (item.clicks || 0), 0))
  if (metricProtected) metricProtected.textContent = String(urls.filter((item) => Boolean(item.hasPassword)).length)
}

async function loadUrls() {
  if (!state.token) {
    renderUrls([], false)
    return
  }

  try {
    const urls = await apiFetch('/myurls')
    renderUrls(urls, true)
  } catch (error) {
    clearSession()
    setSessionUI()
    renderUrls([], false)
    showToast(error.message, true)
  }
}

function fillDemo() {
  const form = document.getElementById('shortenForm')
  if (!form) return
  form.elements.originalUrl.value = 'https://www.example.com/products/spring-launch?ref=campaign'
  form.elements.customAlias.value = 'spring-launch'
  form.elements.password.value = ''
}

function bindHomePage() {
  bindTabs()
  setSessionUI()

  const demoButton = document.getElementById('demoFill')
  if (demoButton) demoButton.addEventListener('click', fillDemo)

  const loginForm = document.getElementById('loginForm')
  const registerForm = document.getElementById('registerForm')
  const shortenForm = document.getElementById('shortenForm')
  const logoutButton = document.getElementById('logoutButton')
  const copyButton = document.getElementById('copyButton')

  if (loginForm) {
    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault()
      const formData = new FormData(loginForm)
      try {
        const data = await apiFetch('/auth/login', {
          method: 'POST',
          body: JSON.stringify(Object.fromEntries(formData.entries()))
        })
        saveSession(data.token, data.user)
        setSessionUI()
        await loadUrls()
        showToast('Logged in successfully')
        loginForm.reset()
      } catch (error) {
        showToast(error.message, true)
      }
    })
  }

  if (registerForm) {
    registerForm.addEventListener('submit', async (event) => {
      event.preventDefault()
      const formData = new FormData(registerForm)
      try {
        const payload = Object.fromEntries(formData.entries())
        await apiFetch('/auth/register', {
          method: 'POST',
          body: JSON.stringify(payload)
        })
        showToast('Account created. You can log in now.')
        registerForm.reset()
        document.querySelector('[data-tab-target="login"]')?.click()
      } catch (error) {
        showToast(error.message, true)
      }
    })
  }

  if (shortenForm) {
    shortenForm.addEventListener('submit', async (event) => {
      event.preventDefault()
      if (!state.token) {
        showToast('Please log in before creating a short link.', true)
        return
      }

      const formData = new FormData(shortenForm)
      const payload = Object.fromEntries(formData.entries())

      try {
        const data = await apiFetch('/shorten', {
          method: 'POST',
          body: JSON.stringify(payload)
        })
        const resultPanel = document.getElementById('resultPanel')
        const shortUrlOutput = document.getElementById('shortUrlOutput')
        if (resultPanel && shortUrlOutput) {
          shortUrlOutput.textContent = data.shortUrl
          shortUrlOutput.href = data.shortUrl
          resultPanel.hidden = false
        }
        shortenForm.reset()
        await loadUrls()
        showToast('Short link created')
      } catch (error) {
        showToast(error.message, true)
      }
    })
  }

  if (logoutButton) {
    logoutButton.addEventListener('click', () => {
      clearSession()
      setSessionUI()
      renderUrls([], false)
      showToast('Logged out')
    })
  }

  if (copyButton) {
    copyButton.addEventListener('click', async () => {
      const shortUrlOutput = document.getElementById('shortUrlOutput')
      if (!shortUrlOutput?.href) return
      try {
        await navigator.clipboard.writeText(shortUrlOutput.href)
        showToast('Short URL copied')
      } catch (error) {
        showToast('Copy failed. Please copy manually.', true)
      }
    })
  }

  loadUrls()
}

function bindProtectedPage() {
  const form = document.getElementById('protectedForm')
  if (!form) return

  const code = window.location.pathname.split('/').filter(Boolean).pop()
  const description = document.getElementById('protectedDescription')
  if (description && code) {
    description.textContent = `Enter the password for ${code} to continue to the original destination.`
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    const passwordInput = document.getElementById('protectedPassword')
    try {
      const data = await apiFetch(`/verify/${code}`, {
        method: 'POST',
        body: JSON.stringify({ password: passwordInput.value })
      })
      showToast('Password verified. Redirecting...')
      window.setTimeout(() => {
        window.location.href = data.originalUrl
      }, 500)
    } catch (error) {
      showToast(error.message, true)
    }
  })
}

if (document.body.dataset.page === 'protected') {
  bindProtectedPage()
} else {
  bindHomePage()
}
