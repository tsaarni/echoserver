/**
 * PersistentValues will bind HTMLElement values (such as form elements) with their persisted values in localStorage.
 * If the value of an element is changed, the new value will be stored in localStorage.
 */
class PersistentValues {
  /**
   * Create a PersistentValues instance.
   * @param {string} key - The key under which values are stored in localStorage.
   */
  constructor(key) {
    this.key = key;
    this.elements = [];
    this.defaultValues = {};
    this.persistedValues = JSON.parse(localStorage.getItem(key)) || {};
  }

  /**
   * Add an element to be persisted.
   * @param {HTMLElement} element - The element to be persisted.
   * @param {any} defaultValue - The default value of the element.
   * @returns {PersistentValues} The instance.
   */
  addElement(element, defaultValue) {
    this.elements.push(element);
    this.defaultValues[element.id] = defaultValue;
    return this;
  }

  /**
   * Bind the elements to their persisted values and set up event listeners for updating changes to localStorage.
   * @returns {PersistentValues} The instance.
   */
  bind() {
    this.elements.forEach((element) => {
      const persistedValue = this.persistedValues[element.id];
      const defaultValue = this.defaultValues[element.id];
      const isCheckbox = element.type === 'checkbox';

      if (isCheckbox) {
        // Checkbox: persisted value is undefined/false/true.
        element.checked = persistedValue === undefined ? defaultValue : persistedValue;
      } else {
        // Other: persisted value is undefined or the value.
        element.value = persistedValue || defaultValue;
      }

      element.addEventListener('change', () => {
        // Read the current value either from the checkbox state or the value.
        const currentValue = isCheckbox ? element.checked : element.value;

        if (currentValue === defaultValue) {
          // If the current value is the default value, remove the persisted value.
          delete this.persistedValues[element.id];
        } else {
          // Otherwise, store the current value.
          this.persistedValues[element.id] = currentValue;
        }
        // Save the current persisted values to localStorage.
        this.save();
      });
    });
    return this;
  }

  /**
   * Save the current values to localStorage.
   * @private
   */
  save() {
    localStorage.setItem(this.key, JSON.stringify(this.persistedValues));
  }
}

function initTheme() {
  const key = 'theme';
  const prefersDark = globalThis.matchMedia('(prefers-color-scheme: dark)').matches;
  let currentTheme = localStorage.getItem(key) || (prefersDark ? 'dark' : 'light');

  const applyTheme = (theme) => {
    document.documentElement.dataset.theme = theme;
    const logo = document.querySelector('img[src*="echoserver-"]');
    if (logo) {
      logo.src = logo.src.replace(/echoserver-(light|dark)\.png/, `echoserver-${theme}.png`);
    }
  };

  applyTheme(currentTheme);

  const btn = document.createElement('button');
  btn.className = 'theme-toggle';
  btn.textContent = currentTheme === 'dark' ? '☀︎' : '☾︎';
  btn.title = 'Toggle dark mode';

  btn.addEventListener('click', () => {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(currentTheme);
    localStorage.setItem(key, currentTheme);
    btn.textContent = currentTheme === 'dark' ? '☀︎' : '☾︎';
  });

  document.body.appendChild(btn);
}

export { PersistentValues, initTheme };
