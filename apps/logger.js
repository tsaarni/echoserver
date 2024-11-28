class Logger {
  constructor(div) {
    this.div = div;
  }

  info(message, payload = null) {
    const timestamp = new Date().toLocaleString(navigator.language);
    const entry = document.createElement('div');

    if (payload) {
      entry.innerHTML = `${timestamp} [INFO] ${message} ${stringifyPayload(payload)}<p>`;
    } else {
      entry.innerHTML = `${timestamp} [INFO] ${message}<p>`;
    }

    this.div.appendChild(entry);
  }

  error(message, payload = null) {
    const timestamp = new Date().toLocaleString(navigator.language);
    const entry = document.createElement('div');

    if (payload) {
      entry.innerHTML = `${timestamp} [ERROR] ${message} ${stringifyPayload(payload)}<p>`;
    } else {
      entry.innerHTML = `${timestamp} [ERROR] ${message}<p>`;
    }
    entry.style.color = 'red';

    this.div.appendChild(entry);
  }

  clear() {
    this.div.innerHTML = '';
  }
}

function stringifyPayload(payload) {
  const pre = document.createElement('pre');

  try {
    payload = JSON.parse(payload);
  } catch {
    // Not JSON string
  }

  try {
    payload = JSON.stringify(payload, null, 2);
  } catch {
    // Not object
  }
  pre.innerHTML = payload;

  return pre.outerHTML;
}

export { Logger };
