(function () {
  const defaultSiteUrl = 'https://example.com';

  function readJson(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return fallback;
      const parsed = JSON.parse(raw);
      return parsed ?? fallback;
    } catch (error) {
      return fallback;
    }
  }

  function writeJson(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (error) {
      return false;
    }
  }

  function getSiteBaseUrl() {
    if (window.location && window.location.origin && window.location.origin !== 'null') {
      return window.location.origin;
    }
    return defaultSiteUrl;
  }

  function getApiBaseUrl() {
    const runtimeConfig = window.__APP_CONFIG__ || {};
    const configured = runtimeConfig.apiBase || runtimeConfig.API_BASE || runtimeConfig.backendUrl || runtimeConfig.BACKEND_URL;
    if (configured) {
      return String(configured).replace(/\/$/, '');
    }
    return getSiteBaseUrl();
  }

  function resolveApiUrl(path) {
    const normalizedPath = String(path || '').trim();
    if (!normalizedPath) return getApiBaseUrl();
    if (/^https?:\/\//i.test(normalizedPath)) return normalizedPath;
    const apiBase = getApiBaseUrl();
    const prefixed = normalizedPath.startsWith('/') ? normalizedPath : `/${normalizedPath}`;
    return `${apiBase}${prefixed}`;
  }

  function formatMoney(value) {
    const currencyValue = Number(value || 0);
    return new Intl.NumberFormat('en-LK', {
      style: 'currency',
      currency: 'LKR',
      maximumFractionDigits: 2
    }).format(currencyValue);
  }

  function setMetaTag(name, content, attr = 'name') {
    let tag = document.querySelector(`meta[${attr}="${name}"]`);
    if (!tag) {
      tag = document.createElement('meta');
      tag.setAttribute(attr, name);
      document.head.appendChild(tag);
    }
    tag.setAttribute('content', content);
  }

  function setCanonical(url) {
    let link = document.querySelector('link[rel="canonical"]');
    const target = url || `${getSiteBaseUrl()}${window.location.pathname}`;
    if (!link) {
      link = document.createElement('link');
      link.rel = 'canonical';
      document.head.appendChild(link);
    }
    link.href = target;
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"'`]/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '`': '&#96;'
    }[char] || char));
  }

  function sanitizeUrl(value, fallback = '#') {
    const raw = String(value ?? fallback).trim();
    if (!raw) return fallback;
    if (/^(?:javascript:|data:|vbscript:)/i.test(raw)) return fallback;
    return raw;
  }

  function safeImageUrl(value, fallback = 'productImage.webp') {
    const url = sanitizeUrl(value, fallback);
    if (/^(?:https?:)?\/\//i.test(url) || /^\//.test(url) || /^\.?\.?\//.test(url) || /^[A-Za-z0-9_\-./]+$/.test(url)) {
      return url;
    }
    return fallback;
  }

  function applySeoDefaults(options = {}) {
    const pageTitle = options.title || document.title || 'Oriflame Sri Lanka';
    const description = options.description || 'Shop skincare, makeup, fragrance and personal care essentials with Oriflame Sri Lanka.';
    const image = safeImageUrl(options.image || `${getSiteBaseUrl()}/productImage.webp`);
    const pageUrl = options.url || `${getSiteBaseUrl()}${window.location.pathname}`;

    document.title = pageTitle;
    setMetaTag('description', description);
    setMetaTag('theme-color', '#141b16');
    setMetaTag('og:title', pageTitle, 'property');
    setMetaTag('og:description', description, 'property');
    setMetaTag('og:type', 'website', 'property');
    setMetaTag('og:url', pageUrl, 'property');
    setMetaTag('og:image', image, 'property');
    setMetaTag('twitter:card', 'summary_large_image');
    setMetaTag('twitter:title', pageTitle, 'name');
    setMetaTag('twitter:description', description, 'name');
    setMetaTag('twitter:image', image, 'name');
    setCanonical(pageUrl);
  }

  window.SiteCore = {
    readJson,
    writeJson,
    formatMoney,
    escapeHtml,
    sanitizeUrl,
    safeImageUrl,
    getApiBaseUrl,
    resolveApiUrl,
    applySeoDefaults,
    getSiteBaseUrl
  };
})();
