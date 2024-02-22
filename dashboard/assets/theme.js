/*!
 * Color mode toggler for Bootstrap's docs (https://getbootstrap.com/)
 * Copyright 2011-2024 The Bootstrap Authors
 * Licensed under the Creative Commons Attribution 3.0 Unported License.
 * 
 * Modified to only use single button.
 */

(() => {
  'use strict'

  const getStoredTheme = () => localStorage.getItem('theme')
  const setStoredTheme = theme => localStorage.setItem('theme', theme)

  // Get theme from storage or browser / OS preference.
  const getPreferredTheme = () => {
    const storedTheme = getStoredTheme()
    if (storedTheme) {
      return storedTheme
    }

    return 'dark'
    // TODO: Auto-use light mode if support is better.
    // return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }

  // Set bootstrap theme.
  const setTheme = theme => {
    if (theme === 'auto') {
      document.documentElement.setAttribute('data-bs-theme', 'dark')
      // TODO: Auto-use light mode if support is better.
      // document.documentElement.setAttribute('data-bs-theme', (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))
    } else {
      document.documentElement.setAttribute('data-bs-theme', theme)
    }
  }

  // Set theme from settings asap.
  setTheme(getPreferredTheme())

  // Switch to next theme.
  const nextTheme = theme => {
    switch (theme) {
      case "light":
        return "dark"
      case "dark":
        return "auto"
      case "auto":
        return "light"
    }
  }

  // Set active icon on toggle button.
  const showActiveTheme = theme => {
    // Update theme switcher value.

    const themeSwitcher = document.querySelector('#theme-switcher')
    if (!themeSwitcher) {
      return
    }
    themeSwitcher.setAttribute('data-theme', theme)

    // Update icon.

    const themeSwitcherIcon = document.querySelector('#theme-switcher i')
    if (!themeSwitcherIcon) {
      return
    }

    switch (theme) {
      case "light":
        themeSwitcherIcon.setAttribute('class', 'bi bi-sun-fill')
        break
      case "dark":
        themeSwitcherIcon.setAttribute('class', 'bi bi-moon-stars-fill')
        break
      case "auto":
        themeSwitcherIcon.setAttribute('class', 'bi bi-circle-half')
        break
    }
  }

  // Set active icon and add click listener.
  const initUI = () => {
    showActiveTheme(getPreferredTheme())

    document.querySelectorAll('#theme-switcher')
      .forEach(toggle => {
        toggle.addEventListener('click', () => {
          const theme = nextTheme(toggle.getAttribute('data-theme'))
          setStoredTheme(theme)
          setTheme(theme)
          showActiveTheme(theme)
        })
      })
  }

  // Watch for browser / OS changes.
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const storedTheme = getStoredTheme()
    if (storedTheme !== 'light' && storedTheme !== 'dark') {
      const theme = getPreferredTheme()
      setTheme(theme)
      showActiveTheme(theme)
    }
  })

  // Init UI when done loading.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initUI);
  } else {
    initUI()
  }
})()
