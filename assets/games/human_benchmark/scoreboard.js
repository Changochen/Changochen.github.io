// Shared persistent scoreboard for level-based games.
// Each call to makeScoreboard(gameKey, opts) returns an isolated API
// that reads/writes localStorage under "<gameKey>History" / "<gameKey>LastStart".
(function () {
  function makeScoreboard(gameKey, options) {
    options = options || {};
    const HISTORY_KEY = gameKey + 'History';
    const LAST_START_KEY = gameKey + 'LastStart';
    const MAX_HISTORY = 20;
    const defaultStart = options.defaultStart || 1;

    function loadHistory() {
      try {
        const raw = localStorage.getItem(HISTORY_KEY);
        const arr = raw ? JSON.parse(raw) : [];
        return Array.isArray(arr) ? arr : [];
      } catch (_) { return []; }
    }
    function saveHistory(arr) {
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(arr)); } catch (_) {}
    }
    function getBestLevel() {
      const h = loadHistory();
      return h.length ? Math.max.apply(null, h.map(r => r.reachedLevel)) : 0;
    }
    function getLastStart() {
      const raw = localStorage.getItem(LAST_START_KEY);
      if (raw == null) return defaultStart;
      const n = parseInt(raw, 10);
      return (isNaN(n) || n < 1) ? defaultStart : Math.min(n, 99);
    }
    function setLastStart(n) {
      try { localStorage.setItem(LAST_START_KEY, String(n)); } catch (_) {}
    }
    function addRun(startLevel, reachedLevel) {
      const h = loadHistory();
      h.unshift({ startLevel, reachedLevel, t: Date.now() });
      while (h.length > MAX_HISTORY) h.pop();
      saveHistory(h);
    }
    function clearHistory() { saveHistory([]); }

    function relativeTime(ts) {
      const diff = Date.now() - ts;
      if (diff < 30000) return 'just now';
      if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
      if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
      return Math.floor(diff / 86400000) + 'd ago';
    }

    function render(scoreboardEl, show, onCleared) {
      const history = loadHistory();
      if (!show || history.length === 0) {
        scoreboardEl.innerHTML = '';
        scoreboardEl.classList.remove('visible');
        return;
      }
      const best = getBestLevel();
      let bestMarked = false;
      const rows = history.map((r) => {
        let isBest = false;
        if (!bestMarked && r.reachedLevel === best) { isBest = true; bestMarked = true; }
        return `<tr${isBest ? ' class="best"' : ''}>
          <td>Lvl ${r.startLevel}</td>
          <td>Lvl ${r.reachedLevel}</td>
          <td class="when">${relativeTime(r.t)}</td>
        </tr>`;
      }).join('');
      scoreboardEl.innerHTML = `
        <div class="board-head">
          <h3>Scoreboard · last ${history.length} run${history.length === 1 ? '' : 's'}</h3>
          <button type="button" class="link" id="clearHistoryBtn">Clear history</button>
        </div>
        <table>
          <thead><tr><th>Start</th><th>Reached</th><th>When</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;
      scoreboardEl.classList.add('visible');
      scoreboardEl.querySelector('#clearHistoryBtn').addEventListener('click', () => {
        if (confirm('Clear all run history?')) {
          clearHistory();
          if (onCleared) onCleared();
        }
      });
    }

    return {
      loadHistory, saveHistory,
      getBestLevel, getLastStart, setLastStart,
      addRun, clearHistory, render,
    };
  }

  window.makeScoreboard = makeScoreboard;
})();
