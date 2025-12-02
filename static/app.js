// static/app.js - externalized from templates/index.html

let knownAttacks = new Set();

// Create (or reuse) the datalist element used for suggestions
function ensureDatalist() {
  let dl = document.getElementById('attacksList');
  if (!dl) {
    dl = document.createElement('datalist');
    dl.id = 'attacksList';
    document.body.appendChild(dl);
    document.getElementById('searchInput').setAttribute('list', 'attacksList');
  }
  // Clear existing options
  dl.innerHTML = '';
  return dl;
}

// Note: autocomplete-by-typing removed. Searches will run on button click (mouse).
// If you want autocomplete later, we can re-enable a click-to-populate suggestions flow.
const inputEl = document.getElementById('searchInput');

// Populate the datalist once when the input gains focus (avoids 1-char debounced autocomplete)
async function populateAttacks() {
  try {
    const dl = ensureDatalist();
    // If already populated, skip
    if (dl.childElementCount > 0) return;
    // Fetch a small, static attacks JSON (written once at startup) for fast suggestions.
    // Falls back to the API if the static file isn't present.
    let resp = await fetch('/static/attacks.json');
    if (!resp.ok) {
      resp = await fetch('/api/attacks?limit=500');
    }
    if (!resp.ok) return;
    const items = await resp.json();
    // items are {id, name}
    items.forEach(it => {
      const opt = document.createElement('option');
      // show both id and name for clarity in the suggestion list
      opt.value = `${it.id} - ${it.name}`;
      dl.appendChild(opt);
      knownAttacks.add(it.id);
    });
  } catch (e) {
    // Ignore silently; suggestions are optional
  }
}

// Populate suggestions on first focus
if (inputEl) {
  inputEl.addEventListener('focus', populateAttacks, { once: true });
}

async function search() {
  const query = document.getElementById("searchInput").value.trim();
  if (!query) return;

  const resultsDiv = document.getElementById("results");
  // Clear previous results
  resultsDiv.textContent = '';

  // Spinner
  const spinnerWrap = document.createElement('div');
  spinnerWrap.className = 'text-center';
  const spinner = document.createElement('div');
  spinner.className = 'spinner-border';
  spinner.setAttribute('role', 'status');
  spinnerWrap.appendChild(spinner);
  resultsDiv.appendChild(spinnerWrap);

  try {
    const resp = await fetch(`/search?q=${encodeURIComponent(query)}`);
    const data = await resp.json();

    // Remove spinner
    resultsDiv.removeChild(spinnerWrap);

    if (data.error) {
      const alert = document.createElement('div');
      alert.className = 'alert alert-warning';
      alert.textContent = `⚠️ ${data.error}`;
      resultsDiv.appendChild(alert);
      return;
    }

    // Card
    const card = document.createElement('div');
    card.className = 'card result-card';

    const header = document.createElement('div');
    header.className = 'card-header bg-primary text-white';
    header.textContent = `${data.query} → D3FEND Countermeasures (${data.total_d3fend} total)`;
    card.appendChild(header);

    const body = document.createElement('div');
    body.className = 'card-body';

    const attacks = Array.isArray(data.attack_matches) ? data.attack_matches : [];
    attacks.forEach(attack => {
      const sub = document.createElement('div');
      sub.className = 'sub-attack';

      const h = document.createElement('h5');
      h.className = 'mt-3';
      h.textContent = `${attack.id} - ${attack.name}`;
      sub.appendChild(h);

      const ul = document.createElement('ul');
      ul.className = 'list-group list-group-flush';

      // Copy the array so we don't mutate the original data. Remove the final
      // (bottom) entry per user request to avoid repeated/duplicate items.
      let items = Array.isArray(attack.d3fend) ? attack.d3fend.slice() : [];
      if (items.length > 0) {
        items.pop();
      }
      items.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-group-item d-flex justify-content-between align-items-start';

        const left = document.createElement('div');

  const strong = document.createElement('strong');
  // Prefer canonical D3FEND id, then ATT&CK ref, then the plain internal id.
  // Do NOT prefix the plain id with `d3f:` when showing in the UI.
  strong.textContent = item.d3fend_id ? item.d3fend_id : (item.attack_ref ? item.attack_ref : item.id);
        left.appendChild(strong);

        // badges
        const badgesWrap = document.createElement('div');
        badgesWrap.className = 'mt-1';

        if (item.type) {
          const b = document.createElement('span');
          b.className = 'badge bg-secondary me-1';
          b.textContent = item.type;
          badgesWrap.appendChild(b);
        }
        if (item.attack_ref) {
          const b = document.createElement('span');
          b.className = 'badge bg-warning text-dark me-1';
          b.textContent = item.attack_ref;
          badgesWrap.appendChild(b);
        }
        if (item.tactic_id) {
          const b = document.createElement('span');
          b.className = 'badge bg-info text-dark me-1';
          b.textContent = item.tactic_id;
          badgesWrap.appendChild(b);
        }
        if (item.d3fend_id) {
          const b = document.createElement('span');
          b.className = 'badge bg-dark text-white';
          b.textContent = item.d3fend_id;
          badgesWrap.appendChild(b);
        }

        const nameDiv = document.createElement('div');
        nameDiv.className = 'mt-1';
        const nameSpan = document.createElement('span');
        nameSpan.textContent = item.name;
        nameDiv.appendChild(nameSpan);

        left.appendChild(badgesWrap);
        left.appendChild(nameDiv);

        const right = document.createElement('a');
        right.href = item.url || '#';
        right.target = '_blank';
        right.className = 'btn btn-sm btn-outline-primary';
        right.textContent = 'View →';

        li.appendChild(left);
        li.appendChild(right);
        ul.appendChild(li);
      });

      sub.appendChild(ul);
      body.appendChild(sub);
    });

    card.appendChild(body);
    resultsDiv.appendChild(card);

  } catch (err) {
    // Remove spinner if still present
    try { resultsDiv.removeChild(spinnerWrap); } catch(e){}
    const errDiv = document.createElement('div');
    errDiv.className = 'alert alert-danger';
    errDiv.textContent = `Error: ${err.message}`;
    resultsDiv.appendChild(errDiv);
  }
}

// Allow pressing Enter in the input box
document.getElementById("searchInput").addEventListener("keypress", e => {
  if (e.key === "Enter") search();
});

// Wire the search button click without using inline event handlers (CSP-compliant)
const searchBtn = document.getElementById('searchBtn');
if (searchBtn) {
  searchBtn.addEventListener('click', () => search());
}

// Progress bar and polling logic removed: mappings now load instantly from SQLite DB
