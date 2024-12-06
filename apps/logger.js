class Logger {
  constructor(div) {
    this.container = div;
    this.container.classList.add('logger');
  }

  info(message, payload = null) {
    this.#log('INFO', message, payload);
  }

  error(message, payload = null) {
    this.#log('ERROR', message, payload);
  }

  #log(level, message, payload = null) {
    const date = new Date();
    const timestamp = date.toLocaleTimeString() + '.' + date.getMilliseconds().toString().padStart(3, '0');

    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'time';
    timestampSpan.textContent = timestamp;

    const levelSpan = document.createElement('span');
    levelSpan.className = `level`;
    levelSpan.textContent = `[${level}]`;

    const messageSpan = document.createElement('span');
    messageSpan.className = 'message';
    messageSpan.textContent = message;

    const entry = document.createElement('div');
    entry.className = `log-entry ${level.toLowerCase()}`;
    entry.appendChild(timestampSpan);
    entry.appendChild(levelSpan);
    entry.appendChild(messageSpan);

    if (payload) {
      entry.appendChild(stringifyPayload(payload));
    }

    this.container.appendChild(entry);
  }

  clear() {
    this.container.innerHTML = '';
  }
}

function stringifyPayload(payload) {
  try {
    payload = JSON.parse(payload);
  } catch {
    // Not JSON string.
  }

  // If payload is an object, pretty print it.
  if (typeof payload === 'object') {
    payload = JSON.stringify(payload, null, 2);
  }

  const lines = payload.split('\n');
  const formattedPayload = document.createElement('div');
  formattedPayload.className = 'payload';

  lines.forEach((line, index) => {
    const lineNumSpan = document.createElement('span');
    lineNumSpan.className = 'line-number';
    lineNumSpan.textContent = index + 1;
    formattedPayload.appendChild(lineNumSpan);
    const lineSpan = document.createElement('span');
    lineSpan.className = 'line';
    lineSpan.textContent = line;
    formattedPayload.appendChild(lineSpan);
    formattedPayload.appendChild(document.createElement('br'));
  });

  return formattedPayload;
}

export { Logger };
