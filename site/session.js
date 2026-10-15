// Plays the hero transcript once: client commands are typed, server replies
// appear as whole lines. Without JavaScript, or with reduced motion, the
// finished transcript is shown as is.
(() => {
  const list = document.getElementById("session");
  if (!list || matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const lines = [...list.children];
  const full = lines.map((li) => li.innerHTML);
  list.classList.add("typing");

  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  async function type(li, html) {
    // Client lines are plain text (entities aside), so type the text content.
    const text = new DOMParser().parseFromString(html, "text/html").body.textContent;
    li.textContent = "";
    li.classList.add("on", "cursor");
    for (let i = 1; i <= text.length; i++) {
      li.textContent = text.slice(0, i);
      await wait(text.length > 20 ? 18 : 40);
    }
    li.classList.remove("cursor");
  }

  (async () => {
    await wait(400);
    for (const [i, li] of lines.entries()) {
      if (li.classList.contains("c")) {
        await type(li, full[i]);
        await wait(160);
      } else {
        await wait(li.classList.contains("note") ? 450 : 90);
        li.classList.add("on");
      }
    }
  })();
})();
