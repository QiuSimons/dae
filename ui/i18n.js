const I18n = (() => {
  let dictionary = {};
  let currentLang = localStorage.getItem('daed-demo-lang') || 
                    (navigator.language.startsWith('zh') ? 'zh' : 'en');

  const getNestedValue = (obj, path) => {
    return path.split('.').reduce((acc, part) => acc && acc[part], obj);
  };

  const loadLocale = async (lang) => {
    try {
      console.log(`[i18n] Loading locale: ${lang}`);
      const resp = await fetch(`./locales/${lang}.json`);
      if (resp.ok) {
        dictionary = await resp.json();
        console.log(`[i18n] Loaded locale: ${lang}`);
      } else {
        console.warn(`[i18n] Failed to load locale: ${lang}, status: ${resp.status}`);
        if (lang !== 'en') {
          return loadLocale('en');
        }
      }
    } catch (e) {
      console.error(`[i18n] Error loading locale: ${lang}`, e);
      if (lang !== 'en') {
         return loadLocale('en');
      }
    }
  };

  const t = (key, params = {}) => {
    let str = getNestedValue(dictionary, key) || key;
    if (typeof str === 'string') {
      Object.keys(params).forEach(k => {
        str = str.replace(new RegExp(`{${k}}`, 'g'), params[k]);
      });
    }
    return str;
  };

  const updateDOM = () => {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (key) {
        const text = t(key);
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
           if(el.type === 'button' || el.type === 'submit') {
              el.value = text;
           } else {
              el.placeholder = text;
           }
        } else if (el.children.length === 0) {
           el.textContent = text;
        } else {
           // If it has children, only replace the first text node child if it exists
           for (const node of el.childNodes) {
             if (node.nodeType === 3 && node.textContent.trim().length > 0) {
               node.textContent = text;
               break;
             }
           }
        }
      }
    });
    
    document.querySelectorAll('[data-i18n-aria]').forEach(el => {
      const key = el.getAttribute('data-i18n-aria');
      if (key) {
        el.setAttribute('aria-label', t(key));
      }
    });

    document.documentElement.lang = currentLang === 'zh' ? 'zh-CN' : 'en';
  };

  const init = async () => {
    await loadLocale(currentLang);
    updateDOM();
    window.dispatchEvent(new Event('languageChanged'));
  };

  const setLanguage = async (lang) => {
    if (currentLang === lang) return;
    currentLang = lang;
    localStorage.setItem('daed-demo-lang', lang);
    await init();
  };

  return {
    init,
    t,
    setLanguage,
    updateDOM,
    get currentLang() { return currentLang; }
  };
})();

// Bind globally for easy access
window.t = I18n.t;
window.I18n = I18n;
