// Small markdown helper for club posts.
// Supports the handful of bits people actually type on a wall.

// Escape the five HTML-significant characters. This runs on the raw post body
// BEFORE any markdown is applied, so the only tags in the output are the ones
// this renderer emits itself. Without it, a member could type raw HTML (e.g.
// <img src=x onerror=...>) that PostBody would inject into every visitor's
// page via dangerouslySetInnerHTML — a stored XSS.
function escapeHtml(src) {
  return String(src ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Only allow links whose scheme can't run script. Relative paths (/mod, #frag)
// and http/https/mailto are fine; javascript:, data:, vbscript: etc. are not.
function safeUrl(url) {
  const trimmed = url.trim();
  if (/^(https?:|mailto:)/i.test(trimmed)) return trimmed;
  if (/^[/#?]/.test(trimmed)) return trimmed;
  if (/^[^:]*$/.test(trimmed)) return trimmed; // no scheme at all -> relative
  return "#";
}

function renderMarkdown(src) {
  const text = escapeHtml(src);

  return text
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, label, url) => `<a href="${safeUrl(url)}">${label}</a>`)
    .replace(/^[-*] (.+)$/gm, "<li>$1</li>")
    .replace(/(<li>.*<\/li>)/s, "<ul>$1</ul>")
    .replace(/\n/g, "<br>");
}

module.exports = { renderMarkdown };
