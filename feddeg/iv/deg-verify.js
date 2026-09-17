// Paste into the anonymous-zone console BEFORE confirming the first vote.
// Records evidence, not a verification verdict. No dependencies or network requests.
(() => {
  'use strict';
  if (!document.querySelector('app-root') || !window.crypto?.getRandomValues) {
    console.error('[ДЭГ] Это не страница голосования. Посмотрите инструкцию: сверху должен быть заголовок «Анонимная зона»');
    return;
  }

  const startedAt = Date.now();
  const rng = [], votes = [], warnings = [];
  const requests = new WeakMap();
  const shownWarnings = new Set();
  let selection = [], exportedCount = 0;
  const elapsed = () => Date.now() - startedAt;
  const tell = text => console.log('[ДЭГ] ' + text);
  const moscowTime = () => new Date(Date.now() + 3 * 3600000).toISOString().replace('Z', '+03:00');
  function warn(text) {
    warnings.push({ t: elapsed(), text });
    if (shownWarnings.has(text)) return;
    shownWarnings.add(text);
    console.warn('[ДЭГ] Внимание: ' + text + ' Сохраните JSON и HAR.');
  }
  // Fail open: evidence collection must not prevent the original vote request.
  function observe(action) {
    try { return action(); }
    catch (_) { warn('Часть данных не записалась.'); }
  }
  function parse(text) {
    try { return JSON.parse(text); }
    catch (_) { return null; }
  }

  function rememberSelection() {
    const cards = [...document.querySelectorAll('app-answer-card')];
    if (!cards.length) return; // Confirmation/completion screens may remove the cards.
    const choices = cards.flatMap((card, index) => {
      if (!card.querySelector('input.ui-checkbox-input:checked')) return [];
      return [{ number: index + 1, text: card.innerText.split('\n')[0].trim(), page: location.pathname }];
    });
    // Angular uses skipLocationChange: the URL can still identify the PREVIOUS ballot.
    // Retain the latest rendered selection across confirmation, not a URL-keyed history.
    selection = choices;
  }
  document.addEventListener('change', () => observe(rememberSelection), true);
  document.addEventListener('click', () => queueMicrotask(() => observe(rememberSelection)), true);

  const originalRandom = crypto.getRandomValues;
  function recordRandom(array) {
    const result = originalRandom.call(this, array);
    // This elliptic/rtk-encrypt version uses 192-byte HMAC-DRBG seeds.
    // NEVER record all sizes: signature nonces can disclose the signing key.
    if (array.byteLength === 192) observe(() => {
      const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      rng.push({ t: elapsed(), n: 192, hex: [...bytes].map(b => b.toString(16).padStart(2, '0')).join('') });
    });
    return result;
  }
  crypto.getRandomValues = recordRandom;

  function beginVote(body, transport) {
    rememberSelection();
    const sent = typeof body === 'string' ? body : null;
    const tx = parse(sent);
    const retry = sent && votes.find(v => v.sent === sent);
    const vote = {
      t: elapsed(), transport, page: location.pathname, sent,
      submittedTransactionId: tx?.id || null, contractId: tx?.contractId || null,
      choices: retry ? retry.choices : selection,
      // Always search the full prefix: a retry can reuse already encrypted bytes.
      // Non-overlapping per-request ranges silently lose entropy on retries.
      from: 0, to: rng.length, status: null, receipt: null, finished: false
    };
    votes.push(vote);
    if (!sent) warn('Не удалось записать тело запроса.');
    if (!rng.length) warn('Случайность не записалась. Возможно, скрипт включили поздно.');
    if (!vote.choices.length) warn('Не удалось зафиксировать отметки на экране.');
    return vote;
  }

  function finishVote(vote, status, receipt) {
    vote.status = status;
    vote.receipt = receipt;
    vote.finished = true;
    const data = parse(receipt)?.data;
    const tx = parse(vote.sent);
    vote.transactionId = data?.transactionId || data?.transaction?.id || null;
    const sentVote = tx?.params?.find(p => p.key === 'vote')?.value;
    const returnedVote = data?.transaction?.params?.find(p => p.key === 'vote')?.value;
    // Merely compares the server's answer. Neither ID nor receipt signature is authenticated here.
    vote.receiptMatches = Boolean(status >= 200 && status < 300 && tx?.id &&
      vote.transactionId === tx.id && sentVote !== undefined && returnedVote === sentVote);
    if (vote.receiptMatches) {
      tell('Голос отправлен. Ответ сервера получен. ID транзакции: ' + (vote.transactionId || 'не найден') + '.');
    } else {
      warn('Ответ сервера не удалось сопоставить с отправленным голосом.');
    }
  }

  function isVote(method, url) {
    return String(method).toUpperCase() === 'POST' &&
      new URL(String(url), location.href).pathname.replace(/\/$/, '') === '/api/vote';
  }
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  function recordOpen(method, url) {
    const result = originalOpen.apply(this, arguments);
    observe(() => requests.set(this, isVote(method, url)));
    return result;
  }
  function recordSend(body) {
    const vote = requests.get(this) && observe(() => beginVote(body, 'xhr'));
    if (vote) this.addEventListener('loadend', () => observe(() => {
      const receipt = this.responseType === 'json' ? JSON.stringify(this.response) : this.responseText;
      finishVote(vote, this.status, receipt);
    }), { once: true });
    try { return originalSend.apply(this, arguments); }
    catch (error) {
      if (vote) observe(() => finishVote(vote, 0, ''));
      throw error; // Preserve the browser's original error for the application.
    }
  }
  XMLHttpRequest.prototype.open = recordOpen;
  XMLHttpRequest.prototype.send = recordSend;

  // The reviewed frontend uses XHR. Support string-body fetch too, without delaying it.
  const originalFetch = window.fetch;
  function recordFetch(input, init) {
    const request = input instanceof Request ? input : null;
    const matched = observe(() => isVote(init?.method || request?.method || 'GET', request?.url || input));
    const vote = matched && observe(() => beginVote(init?.body, 'fetch'));
    // Request streams aren't consumed: the report explicitly warns that HAR is needed.
    let promise;
    try { promise = originalFetch.apply(this, arguments); }
    catch (error) {
      if (vote) observe(() => finishVote(vote, 0, ''));
      throw error;
    }
    if (vote) promise.then(response => {
      response.clone().text().then(text => observe(() => finishVote(vote, response.status, text)))
        .catch(() => { observe(() => finishVote(vote, response.status, '')); warn('Не удалось прочитать ответ сервера.'); });
    }, () => observe(() => finishVote(vote, 0, '')))
      .catch(() => { observe(() => finishVote(vote, 0, '')); warn('Не удалось получить ответ сервера.'); });
    return promise;
  }
  if (originalFetch) window.fetch = recordFetch;

  function status() {
    return {
      requests: votes.length, finished: votes.filter(v => v.finished).length, draws: rng.length,
      hooksIntact: crypto.getRandomValues === recordRandom &&
        XMLHttpRequest.prototype.open === recordOpen && XMLHttpRequest.prototype.send === recordSend &&
        (!originalFetch || window.fetch === recordFetch),
      warnings: warnings.length
    };
  }
  function report() {
    return {
      v: 2, page: location.origin + location.pathname, time: moscowTime(), ua: navigator.userAgent,
      startedAt: new Date(startedAt + 3 * 3600000).toISOString().replace('Z', '+03:00'),
      status: status(), warnings, rng, votes
    };
  }
  function save() {
    const text = JSON.stringify(report());
    console.log(text); // One complete JSON string, also recoverable with DevTools copy().
    observe(() => {
      const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'deg-verify-' + moscowTime().replace(/[:.]/g, '-') + '.json';
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    });
    tell('JSON должен автоматически скачаться. Если в папке загрузок ничего нет, скопируйте и прикрепите JSON из предыдущего сообщения вручную. Не забудьте сохранить HAR-файл!');
  }
  window.__degVerify = { status, report, save };
  observe(rememberSelection);
  tell('Скрипт работает. Голосуйте обычно. После последнего бюллетеня JSON скачается автоматически.');
  if (/complete/.test(location.pathname)) warn('Скрипт включён после голосования; предыдущий голос восстановить нельзя.');

  let hookWarning = false;
  setInterval(() => observe(() => {
    if (!status().hooksIntact && !hookWarning) {
      hookWarning = true;
      warn('Перехват изменён другим кодом; полнота записи не гарантируется.');
    }
    // Counts of requests/can-vote calls are NOT counts of successfully cast ballots.
    // Use the captured frontend's final-page control; skip/retry flows then also work.
    const finalPage = document.querySelector('app-final-page');
    const done = finalPage && /Вернуться на портал/.test(finalPage.innerText);
    if (done && votes.length > exportedCount && votes.every(v => v.finished)) {
      exportedCount = votes.length;
      save();
    }
  }), 500);
})();
