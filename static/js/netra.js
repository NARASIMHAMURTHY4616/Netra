/* ═══════════════════════════════════════════════════════════════
   netra.js — Netra Security
   Client-side utilities: flash auto-dismiss, table sort,
   copy-to-clipboard feedback, scan row highlight.
   No dependencies — vanilla JS only.
   ═══════════════════════════════════════════════════════════════ */

'use strict';

/* ── DOMContentLoaded guard ─────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initFlashAutoDismiss();
  initTableSort();
  initScanRowLinks();
  initSeverityRowHighlight();
});


/* ══════════════════════════════════════════════════════════════
   1. FLASH AUTO-DISMISS
   Success flashes disappear after 4 s with a fade-out.
   Error/info flashes stay until manually closed.
══════════════════════════════════════════════════════════════ */
function initFlashAutoDismiss() {
  const successes = document.querySelectorAll('.flash--success');
  successes.forEach(flash => {
    setTimeout(() => dismissFlash(flash), 4000);
  });
}

function dismissFlash(el) {
  el.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
  el.style.opacity    = '0';
  el.style.transform  = 'translateY(-4px)';
  setTimeout(() => el.remove(), 420);
}


/* ══════════════════════════════════════════════════════════════
   2. TABLE SORT
   Click any <th> in .data-table to sort that column.
   Click again to reverse. Works on both dashboard and findings.
══════════════════════════════════════════════════════════════ */
function initTableSort() {
  document.querySelectorAll('.data-table').forEach(table => {
    const headers = table.querySelectorAll('thead th');

    headers.forEach((th, colIndex) => {
      th.style.cursor   = 'pointer';
      th.style.userSelect = 'none';
      th.setAttribute('title', 'Click to sort');

      // Add sort indicator span
      const indicator = document.createElement('span');
      indicator.className = 'sort-indicator';
      indicator.textContent = ' ↕';
      indicator.style.cssText = 'opacity:0.3; font-size:0.7em; margin-left:4px;';
      th.appendChild(indicator);

      let ascending = true;

      th.addEventListener('click', () => {
        // Reset all indicators
        headers.forEach(h => {
          const ind = h.querySelector('.sort-indicator');
          if (ind) { ind.textContent = ' ↕'; ind.style.opacity = '0.3'; }
        });

        // Update clicked indicator
        indicator.textContent = ascending ? ' ↑' : ' ↓';
        indicator.style.opacity = '1';

        sortTable(table, colIndex, ascending);
        ascending = !ascending;
      });
    });
  });
}

function sortTable(table, colIndex, ascending) {
  const tbody = table.querySelector('tbody');
  if (!tbody) return;

  const rows = Array.from(tbody.querySelectorAll('tr'));

  // Severity sort weight (so clicking severity col sorts logically)
  const sevWeight = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

  rows.sort((a, b) => {
    const aCell = a.querySelectorAll('td')[colIndex];
    const bCell = b.querySelectorAll('td')[colIndex];
    if (!aCell || !bCell) return 0;

    let aVal = aCell.textContent.trim().toUpperCase();
    let bVal = bCell.textContent.trim().toUpperCase();

    // Numeric sort for line numbers and counts
    const aNum = parseFloat(aVal.replace(/[^0-9.]/g, ''));
    const bNum = parseFloat(bVal.replace(/[^0-9.]/g, ''));

    if (!isNaN(aNum) && !isNaN(bNum)) {
      return ascending ? aNum - bNum : bNum - aNum;
    }

    // Severity-aware sort
    if (aVal in sevWeight && bVal in sevWeight) {
      return ascending
        ? sevWeight[aVal] - sevWeight[bVal]
        : sevWeight[bVal] - sevWeight[aVal];
    }

    // Fallback: lexicographic
    if (aVal < bVal) return ascending ? -1 :  1;
    if (aVal > bVal) return ascending ?  1 : -1;
    return 0;
  });

  // Re-append sorted rows
  rows.forEach(row => tbody.appendChild(row));
}


/* ══════════════════════════════════════════════════════════════
   3. SCAN ROW CLICK-THROUGH
   Clicking anywhere on a dashboard scan row navigates to its
   findings page (the "View" link is already there, this just
   makes the whole row feel clickable).
══════════════════════════════════════════════════════════════ */
function initScanRowLinks() {
  const table = document.getElementById('scanTable');
  if (!table) return;

  table.querySelectorAll('tbody .table-row').forEach(row => {
    const link = row.querySelector('.file-link');
    if (!link) return;

    row.style.cursor = 'pointer';

    row.addEventListener('click', (e) => {
      // Don't intercept button/link/form clicks
      if (e.target.closest('a, button, form')) return;
      window.location.href = link.href;
    });
  });
}


/* ══════════════════════════════════════════════════════════════
   4. SEVERITY ROW HIGHLIGHT ON HOVER
   Findings table rows get a subtle left-glow matching their
   severity colour on hover, in addition to the CSS bg change.
══════════════════════════════════════════════════════════════ */
function initSeverityRowHighlight() {
  const sevGlow = {
    critical: 'rgba(255,71,87,0.08)',
    high:     'rgba(255,107,53,0.08)',
    medium:   'rgba(255,165,2,0.08)',
    low:      'rgba(0,255,157,0.06)',
  };

  document.querySelectorAll('.finding-row').forEach(row => {
    const sev = (row.dataset.severity || '').toLowerCase();
    const glow = sevGlow[sev];
    if (!glow) return;

    row.addEventListener('mouseenter', () => {
      row.querySelectorAll('td').forEach(td => {
        td.style.backgroundColor = glow;
      });
    });

    row.addEventListener('mouseleave', () => {
      row.querySelectorAll('td').forEach(td => {
        td.style.backgroundColor = '';
      });
    });
  });
}
