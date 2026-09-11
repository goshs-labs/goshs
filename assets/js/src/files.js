// ══ FILE OPERATIONS ══
import { ST, esc, fmtBytes } from './state.js';
import { openModal, closeModal, toast } from './modals.js';

export function navigateTo(path) {
  window.location.href = path;
}

export function filterFiles() {
  const q = document.getElementById("file-search").value.toLowerCase();
  document.querySelectorAll("#file-tbody tr").forEach((tr) => {
    const name = (tr.dataset.name || "").toLowerCase();
    tr.style.display = !q || name.includes(q) ? "" : "none";
  });
}

let sortDir = { name: true, size: true, mtime: true };
export function sortTable(col) {
  const asc = (sortDir[col] = !sortDir[col]);
  const tbody = document.getElementById("file-tbody");
  const rows = Array.from(tbody.querySelectorAll("tr[data-name]"));
  rows.sort((a, b) => {
    let va = a.dataset[col] || "",
      vb = b.dataset[col] || "";
    if (col === "size" || col === "mtime") {
      va = parseFloat(va) || 0;
      vb = parseFloat(vb) || 0;
      return asc ? va - vb : vb - va;
    }
    return asc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
  rows.forEach((r) => tbody.appendChild(r));
  document.querySelectorAll(".file-table th[id]").forEach((th) => {
    th.classList.remove("sorted");
    th.querySelector(".sort-arrow").textContent = "↕";
  });
  const th = document.getElementById("th-" + col);
  if (th) {
    th.classList.add("sorted");
    th.querySelector(".sort-arrow").textContent = asc ? "↑" : "↓";
  }
}

function toggleAllChecks(el) {
  document
    .querySelectorAll(".row-check-item")
    .forEach((c) => (c.checked = el.checked));
  updateBulkBar();
}
export function updateBulkBar() {
  const checked = document.querySelectorAll(".row-check-item:checked").length;
  const bar = document.getElementById("bulk-bar");
  bar.classList.toggle("show", checked > 0);
  document.getElementById("bulk-count").textContent = checked + " selected";
}
export function clearSelection() {
  document
    .querySelectorAll(".row-check-item")
    .forEach((c) => (c.checked = false));
  const all = document.getElementById("chk-all");
  if (all) all.checked = false;
  updateBulkBar();
}
function getSelectedNames() {
  return Array.from(document.querySelectorAll(".row-check-item:checked"))
    .map((c) => c.closest("tr").dataset.name)
    .filter(Boolean);
}
function getSelectedValues() {
  return Array.from(document.querySelectorAll(".row-check-item:checked"))
    .map((c) => c.closest("tr").dataset.value)
    .filter(Boolean);
}
export function downloadSelected() {
  // This one takes all the selected and forms the right zip download
  const url = new URL(window.location.href);
  getSelectedValues().forEach((val) => {
    url.searchParams.append("file", val);
  });
  url.searchParams.append("bulk", "true");
  window.open(url.href, "_blank");
  clearSelection();
}
export function downloadBulk() {
  // This one selects everything in the current view and forms the right zip download
  document.querySelectorAll("#file-tbody tr[data-name]").forEach((tr) => {
    if (tr.style.display !== "none") {
      const cb = tr.querySelector(".row-check-item");
      if (cb) cb.checked = true;
    }
  });
  updateBulkBar();
  downloadSelected();
}
function deleteSelected() {
  const vals = getSelectedValues();
  if (!vals.length) return;
  if (!confirm(`Delete ${vals.length} item(s)?`)) return;
  Promise.all(vals.map((val) => deleteFile(val, true)))
    .then(() => location.reload())
    .catch(() => toast("Delete failed", "error"));
}
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : "";
}
export function deleteFile(path, bulk) {
  let ok;
  !bulk
    ? (ok = confirm("Do you really want to delete the file or directory?"))
    : (ok = true);

  if (ok) {
    var url = "";
    location.protocol !== "https:"
      ? (url = "http://" + window.location.host + path)
      : (url = "https://" + window.location.host + path);
    fetch(url, {
      method: "DELETE",
      headers: { "X-CSRF-Token": getCsrfToken() },
    })
      .then(() => location.reload())
      .catch(() => toast("Delete failed", "error"));
  }
}

// ══ UPLOAD ══
export function openUpload() {
  openModal("upload-modal");
}
export function openMkdir() {
  openModal("mkdir-modal");
  setTimeout(() => document.getElementById("mkdir-input").focus(), 50);
}

// addPending merges {file, path} entries into the pending list, de-duplicating
// by relative path + size so the same file dropped twice is not queued twice.
function addPending(entries) {
  entries.forEach(({ file, path }) => {
    if (
      !ST.pendingUploads.find((p) => p.path === path && p.file.size === file.size)
    ) {
      ST.pendingUploads.push({ file, path });
    }
  });
  renderUploadList();
}
export function handleFileSelect(files) {
  // Input elements expose the folder structure via webkitRelativePath (set when
  // the <input webkitdirectory> folder picker is used); plain file inputs leave
  // it empty, so fall back to the flat name.
  addPending(
    Array.from(files).map((f) => ({
      file: f,
      path: f.webkitRelativePath || f.name,
    })),
  );
}
function renderUploadList() {
  const list = document.getElementById("upload-file-list");
  list.innerHTML = "";
  ST.pendingUploads.forEach((p, i) => {
    const item = document.createElement("div");
    item.className = "upload-file-item";
    item.innerHTML = `<span class="fname">${esc(p.path)}</span><span class="fsize">${fmtBytes(p.file.size)}</span>
<button class="fremove" onclick="removeUpload(${i})">✕</button>`;
    list.appendChild(item);
  });
}
export function removeUpload(i) {
  ST.pendingUploads.splice(i, 1);
  renderUploadList();
}
export function startUpload() {
  if (!ST.pendingUploads.length) {
    toast("No files selected", "warn");
    return;
  }
  const fd = new FormData();
  // The third argument sets the multipart part filename to the relative path, so
  // the server can recreate the folder tree (updown.go parses it from the raw
  // Content-Disposition header).
  ST.pendingUploads.forEach((p) => fd.append("file", p.file, p.path));
  const wrap = document.getElementById("upload-progress-wrap");
  const bar = document.getElementById("upload-progress-bar");
  wrap.style.display = "block";
  bar.style.width = "0";

  const xhr = new XMLHttpRequest();
  xhr.open("POST", `${window.location.href}upload`);
  xhr.setRequestHeader("X-CSRF-Token", getCsrfToken());
  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) bar.style.width = (e.loaded / e.total) * 100 + "%";
  };
  xhr.onload = () => {
    if (xhr.status === 200) {
      toast("Upload complete!", "success");
      closeModal("upload-modal");
      ST.pendingUploads = [];
      setTimeout(() => location.reload(), 600);
    } else if (xhr.status === 413) {
      const limitBytes = parseInt(
        document.querySelector('meta[name="max-upload"]')?.content || "0",
        10,
      );
      const msg =
        limitBytes > 0
          ? "Upload rejected: exceeds the " +
            fmtBytes(limitBytes) +
            " server limit"
          : "Upload rejected: file too large";
      toast(msg, "error");
    } else toast("Upload failed: " + xhr.statusText, "error");
  };
  xhr.onerror = () => toast("Upload failed", "error");
  xhr.send(fd);
}
export function createDir() {
  const name = document.getElementById("mkdir-input").value.trim();
  if (!name) return;

  const target = name.endsWith("/") ? name : name + "/";
  fetch(target, {
    method: "POST",
    headers: { "X-CSRF-Token": getCsrfToken() },
  })
    .then((r) => {
      // if response http.Created
      if (r.status === 201) {
        toast("Created: " + name, "success");
        closeModal("mkdir-modal");
        setTimeout(() => location.reload(), 600);
      } else toast("Failed", "error");
    })
    .catch(() => toast("Network error", "error"));
}

// ══ DRAG-DROP ══
// Recursively walk a dropped DataTransfer entry tree, collecting {file, path}
// pairs. path uses forward slashes so it matches webkitRelativePath and the
// server's relative-path handling.
function readEntries(reader) {
  return new Promise((resolve, reject) => reader.readEntries(resolve, reject));
}
async function traverseEntry(entry, prefix, out) {
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) =>
      entry.file(resolve, reject),
    );
    out.push({ file, path: prefix + entry.name });
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    // readEntries returns at most 100 entries per call, so drain in batches.
    let batch;
    do {
      batch = await readEntries(reader);
      for (const child of batch) {
        await traverseEntry(child, prefix + entry.name + "/", out);
      }
    } while (batch.length > 0);
  }
}
// itemsToEntries turns a dropped DataTransferItemList into {file, path} pairs,
// preserving any folder structure. webkitGetAsEntry()/getAsFile() must be called
// synchronously before the first await, or the item list becomes invalid.
async function itemsToEntries(items) {
  const roots = [];
  for (const it of items) {
    if (it.kind !== "file") continue;
    const entry = it.webkitGetAsEntry && it.webkitGetAsEntry();
    if (entry) {
      roots.push(entry);
    } else {
      const f = it.getAsFile();
      if (f) roots.push({ isFile: true, name: f.name, _file: f });
    }
  }
  const out = [];
  for (const root of roots) {
    if (root._file) {
      out.push({ file: root._file, path: root.name });
    } else {
      await traverseEntry(root, "", out);
    }
  }
  return out;
}
// entriesFromDrop prefers the entry API (folder-aware) and falls back to the
// flat FileList when it is unavailable.
async function entriesFromDrop(dt) {
  if (dt.items && dt.items.length && dt.items[0].webkitGetAsEntry) {
    return itemsToEntries(dt.items);
  }
  return Array.from(dt.files).map((f) => ({ file: f, path: f.name }));
}
function initDrop() {
  const overlay = document.getElementById("drop-overlay");
  let dragCnt = 0;
  document.addEventListener("dragenter", (e) => {
    if (!e.dataTransfer.types.includes("Files")) return;
    dragCnt++;
    overlay.classList.add("active");
    e.preventDefault();
  });
  document.addEventListener("dragleave", () => {
    if (--dragCnt <= 0) {
      dragCnt = 0;
      overlay.classList.remove("active");
    }
  });
  document.addEventListener("dragover", (e) => {
    e.preventDefault();
  });
  document.addEventListener("drop", async (e) => {
    e.preventDefault();
    dragCnt = 0;
    overlay.classList.remove("active");
    const entries = await entriesFromDrop(e.dataTransfer);
    if (entries.length) {
      addPending(entries);
      openModal("upload-modal");
    }
  });
  // modal drop area
  const mda = document.getElementById("modal-drop-area");
  if (mda) {
    mda.addEventListener("dragover", (e) => {
      e.preventDefault();
      mda.classList.add("hover");
    });
    mda.addEventListener("dragleave", () => mda.classList.remove("hover"));
    mda.addEventListener("drop", async (e) => {
      e.preventDefault();
      mda.classList.remove("hover");
      addPending(await entriesFromDrop(e.dataTransfer));
    });
  }
}

export function initFiles() {
  initDrop();
}
