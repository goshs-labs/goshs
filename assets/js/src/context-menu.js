// ══ CONTEXT MENU ══
import { previewFile, getPreviewType } from './preview.js';
import { deleteFile } from './files.js';
import { shareFile } from './share.js';
import { registerCloseCtx } from './modals.js';

export function initContextMenu() {
  const menu = document.getElementById("ctx-menu");
  document.getElementById("file-tbody").addEventListener("contextmenu", (e) => {
    const tr = e.target.closest("tr[data-name]");
    if (!tr || !tr.dataset.name || tr.dataset.name === "..") return;
    e.preventDefault();
    const name = tr.dataset.name;
    const isDir = tr.dataset.isdir === "true";
    const previewType = !isDir && getPreviewType(name);
    document.getElementById("ctx-download").style.display = isDir ? "none" : "";
    document.getElementById("ctx-preview").style.display = previewType ? "" : "none";
    document.getElementById("ctx-preview").onclick = () => {
      previewFile(name);
      closeCtx();
    };
    document.getElementById("ctx-open").onclick = () => {
      window.open(name + (isDir ? "/" : ""), "_blank");
      closeCtx();
    };
    document.getElementById("ctx-download").onclick = () => {
      const a = document.createElement("a");
      a.href = name;
      a.download = name;
      a.click();
      closeCtx();
    };
    document.getElementById("ctx-share").onclick = () => {
      shareFile(tr.dataset.value);
      closeCtx();
    };
    document.getElementById("ctx-delete").onclick = () => {
      deleteFile(tr.dataset.value);
      closeCtx();
    };
    menu.style.left = Math.min(e.clientX, window.innerWidth - 180) + "px";
    menu.style.top = Math.min(e.clientY, window.innerHeight - 180) + "px";
    menu.classList.add("open");
  });
  document.addEventListener("click", closeCtx);
}

function closeCtx() {
  document.getElementById("ctx-menu").classList.remove("open");
}

// Register closeCtx with modals so Escape key can call it
registerCloseCtx(closeCtx);
