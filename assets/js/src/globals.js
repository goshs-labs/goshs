// Expose functions referenced from HTML onclick/oninput/onchange handlers
// esbuild wraps modules in a closure, so these must be assigned to window

import {
  exportHTTP, exportDNS, exportSMTP, exportSMB, exportLDAP, exportAllLogs,
  clearHTTP, clearDNS, clearSMTP, clearSMB, clearLDAP,
  filterHTTP, renderDNS, renderSMB, renderLDAP, renderSMTP,
  openHTMLPreview, openLightbox, toggleHTTPDetail,
} from "./collab.js";
import {
  navigateTo, filterFiles, sortTable, clearSelection,
  downloadSelected, downloadBulk, deleteFile, updateBulkBar,
  startUpload, openUpload, openMkdir, handleFileSelect, createDir, removeUpload,
} from "./files.js";
import {
  toggleTheme, filterEmbedded, sortEmbedded, copyEmbLink,
  switchPanel, switchCollab,
} from "./theme.js";
import { previewFile } from "./preview.js";
import {
  sendChat, copyMessage, deleteMessage, downloadChat, setNick,
  reactMessage, toggleReactionPicker, cancelEdit,
  openChatUpload, handleChatFile, toggleNotifications,
} from "./chat.js";
import {
  shareFile, showQR, showShareQR,
  generateShareLink, deleteShareLink, copyShareUrl,
} from "./share.js";
import { openModal, closeModal } from "./modals.js";
import {
  spawnListenerTab, switchCatcherTab, copyListenerCommand,
  updateGeneratorOutput, copyGeneratorOutput,
  startCatcherListener, restartCatcherListener, stopCatcherListener,
  showRestartForm, connectCatcherSession, killCatcherSession,
  resizeCatcherTerm, toggleLineMode, upgradeCatcherUnix, upgradeCatcherWindows,
} from "./catcher.js";

Object.assign(window, {
  toggleTheme, switchPanel, switchCollab,
  clearHTTP, clearDNS, clearSMTP, clearSMB, clearLDAP,
  filterHTTP, renderDNS, renderSMB, renderLDAP, renderSMTP,
  exportHTTP, exportDNS, exportSMTP, exportSMB, exportLDAP, exportAllLogs,
  openHTMLPreview, openLightbox, toggleHTTPDetail,
  previewFile,
  navigateTo, filterFiles, sortTable, clearSelection,
  downloadSelected, downloadBulk, deleteFile,
  updateBulkBar, startUpload, openUpload, openMkdir, handleFileSelect, createDir, removeUpload,
  sendChat, copyMessage, deleteMessage, downloadChat, setNick,
  reactMessage, toggleReactionPicker, cancelEdit,
  openChatUpload, handleChatFile, toggleNotifications,
  shareFile, showQR, showShareQR, generateShareLink, deleteShareLink, copyShareUrl,
  openModal, closeModal,
  filterEmbedded, sortEmbedded, copyEmbLink,
  spawnListenerTab, switchCatcherTab, copyListenerCommand,
  updateGeneratorOutput, copyGeneratorOutput,
  startCatcherListener, restartCatcherListener, stopCatcherListener,
  showRestartForm, connectCatcherSession, killCatcherSession,
  resizeCatcherTerm, toggleLineMode, upgradeCatcherUnix, upgradeCatcherWindows,
});
