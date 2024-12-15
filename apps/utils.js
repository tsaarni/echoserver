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
      element.value = this.persistedValues[element.id] || this.defaultValues[element.id];
      element.addEventListener('change', () => {
        if (element.value === this.defaultValues[element.id]) {
          delete this.persistedValues[element.id];
        } else {
          this.persistedValues[element.id] = element.value;
        }
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

export { PersistentValues };
