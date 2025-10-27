/* ================================================================= */
/* === PHẦN 1: LOGIC TÌM KIẾM CHÍNH (Fuse.js) === */
/* ================================================================= */

const fuseOptions = {
  includeScore: true,
  threshold: 0.3,
  keys: [
    { name: 'title', weight: 0.4 },
    { name: 'tags', weight: 0.3 },
    { name: 'content', weight: 0.2 },
    { name: 'code_snippets.command', weight: 0.1 },
    { name: 'category', weight: 0.1 }
  ]
};
let knowledgeDataMap = {}; // Map để truy cập nhanh knowledgeData
let fuse; // Khởi tạo fuse sau khi có knowledgeData

// Hàm copy code (đã cải tiến)
function copyCode(buttonElement) {
    const preElement = buttonElement.closest('pre');
    const codeElement = preElement.querySelector('code');
    if (codeElement) {
        navigator.clipboard.writeText(codeElement.textContent || codeElement.innerText)
            .then(() => {
                buttonElement.textContent = translations[appState.currentLang]?.copied || 'Copied!';
                setTimeout(() => { buttonElement.textContent = translations[appState.currentLang]?.copy || 'Copy'; }, 1500);
            })
            .catch(err => {
                console.error('Failed to copy text: ', err);
            });
    }
}

// Hàm escape HTML mạnh mẽ
function escapeHTML(str) {
    if (!str) return '';
    const element = document.createElement('div');
    element.textContent = str;
    return element.innerHTML;
}

// Hàm hiển thị kết quả Knowledge Base (đã cải tiến)
// *** THAY ĐỔI: Hàm displayResults xử lý xen kẽ content và code ***
// script.js

// ... (fuseOptions, knowledgeDataMap, fuse, copyCode, escapeHTML giữ nguyên) ...

// *** THAY ĐỔI: Hàm displayResults - Thay thế placeholder bằng code_snippets ***
function displayResults(results, targetIP, kaliIP) {
  const resultsContainer = document.getElementById('results');
  resultsContainer.innerHTML = '';

  if (!results || results.length === 0) {
    let msgKey = (appState.currentView === 'bookmarks') ? 'noBookmarks' : 'noResults';
    if (appState.currentView === 'bookmarks' && (!appState.bookmarks || appState.bookmarks.length === 0)) {
        msgKey = 'noBookmarks';
    }
    resultsContainer.innerHTML = `<p style="text-align: center;">${translations[appState.currentLang]?.[msgKey] || translations['en']?.[msgKey] || 'No results.'}</p>`;
    return;
  }

  results.forEach(({ item }) => {
    if (!item || !item.id || !item.title || !item.category || !item.source_file) {
        console.warn("Skipping item with missing essential data:", item);
        return;
    }

    const resultCard = document.createElement('div');
    resultCard.classList.add('result-card');
    const isBookmarked = appState.bookmarks.includes(item.id);

    // 1. Header (Giữ nguyên)
    let cardHTML = `
        <div class="card-header">
            <h3>${escapeHTML(item.title)} <span class="category-badge">${escapeHTML(item.category)}</span></h3>
            <button class="bookmark-toggle-btn ${isBookmarked ? 'bookmarked' : ''}" data-key="${escapeHTML(item.id)}" title="${translations[appState.currentLang]?.bookmarkAction || 'Bookmark'}">
            </button>
        </div>`;

    // 2. Chuẩn bị các khối <pre> từ code_snippets
    const codeBlocksHTML = [];
    if (item.code_snippets && Array.isArray(item.code_snippets) && item.code_snippets.length > 0) {
        item.code_snippets.forEach(snippet => {
           if(snippet && snippet.command) {
               let command = snippet.command;
               if (targetIP) command = command.replace(/<target_ip>|\[TARGET_IP\]/g, targetIP);
               if (kaliIP) command = command.replace(/<kali_ip>|\[KALI_IP\]/g, kaliIP);
               const escapedCommand = escapeHTML(command);
               const langClass = snippet.language ? `language-${escapeHTML(snippet.language)}` : 'language-plaintext';
               // Tạo chuỗi HTML cho khối pre và lưu vào mảng
               codeBlocksHTML.push(
                   `<pre><code class="${langClass}">${escapedCommand}</code><button class="copy-btn" onclick="copyCode(this)">${translations[appState.currentLang]?.copy || 'Copy'}</button></pre>`
               );
           }
        });
    }

    // 3. Xử lý Content: Thay backtick bằng placeholder, xử lý markdown
    let contentProcessedHTML = '';
    if (item.content) {
        let processedContent = item.content;

        // Thay thế IP placeholders TRƯỚC KHI xử lý backtick/markdown
        if (targetIP) processedContent = processedContent.replace(/<target_ip>|\[TARGET_IP\]/g, targetIP);
        if (kaliIP) processedContent = processedContent.replace(/<kali_ip>|\[KALI_IP\]/g, kaliIP);

        // Thay thế `code` bằng placeholder @@CODE@@
        // Đếm số lượng placeholder để khớp với codeBlocksHTML
        let placeholderCount = 0;
        processedContent = processedContent.replace(/`([^`]+)`/g, () => {
             // Chỉ thay thế nếu còn code block tương ứng
             if (placeholderCount < codeBlocksHTML.length) {
                 placeholderCount++;
                 return '@@CODE@@';
             }
             return ''; // Bỏ qua backtick nếu không đủ code block
        });

        // Escape HTML và xử lý markdown cơ bản (bold, list)
        processedContent = escapeHTML(processedContent);
        processedContent = processedContent.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        processedContent = processedContent.replace(/\n/g, '<br>'); // Xuống dòng

        // Xử lý list item
        let listStarted = null; // null, 'ul', 'ol'
        const lines = processedContent.split('<br>');
        let tempHTML = '';
        lines.forEach(line => {
             const trimmedLine = line.trim();
             // *** SỬA LỖI: Regex cần kiểm tra ký tự escape HTML của '*' (&lowast;) ***
             const ulMatch = trimmedLine.match(/^(?:&lowast;|\*)\s+(.*)/); // Chấp nhận cả '*' và '&lowast;'
             const olMatch = trimmedLine.match(/^(\d+)\.\s+(.*)/);

             if (ulMatch) {
                 if (!listStarted || listStarted !== 'ul') {
                     if(listStarted) tempHTML += `</${listStarted}>`;
                     tempHTML += '<ul>';
                     listStarted = 'ul';
                 }
                 tempHTML += `<li>${ulMatch[1]}</li>`; // Đã escape ở trên
             } else if (olMatch) {
                 if (!listStarted || listStarted !== 'ol') {
                     if(listStarted) tempHTML += `</${listStarted}>`;
                     tempHTML += '<ol>';
                     listStarted = 'ol';
                 }
                 tempHTML += `<li>${olMatch[2]}</li>`; // Đã escape ở trên
             }
             else {
                 if (listStarted) {
                     tempHTML += `</${listStarted}>`;
                     listStarted = null;
                 }
                 if(trimmedLine || line.includes('@@CODE@@')) { // Giữ lại dòng chứa placeholder
                    // Thay thế placeholder @@CODE@@ bằng code block
                    let lineWithCode = line;
                    let codeIndex = 0; // Index cho codeBlocksHTML
                    lineWithCode = lineWithCode.replace(/@@CODE@@/g, () => {
                         // Lấy code block tiếp theo, nếu có
                        const block = codeBlocksHTML[codeIndex] || '';
                        codeIndex++; // Di chuyển đến code block tiếp theo cho lần thay thế sau (nếu có nhiều trên 1 dòng)
                        return block; // Chèn khối <pre> vào vị trí placeholder
                    });

                    // Bọc dòng kết quả bằng <p> nếu nó không phải là code block hoàn chỉnh
                    if (!lineWithCode.startsWith('<pre>')) {
                        tempHTML += `<p>${lineWithCode}</p>`;
                    } else {
                        tempHTML += lineWithCode; // Thêm <pre> trực tiếp
                    }
                 }
             }
        });
        if (listStarted) tempHTML += `</${listStarted}>`;
        contentProcessedHTML = tempHTML;

        // *** QUAN TRỌNG: Cập nhật lại index cho lần thay thế placeholder tiếp theo ***
        // Vì mỗi lần gọi replace @@CODE@@ ở trên chỉ dùng index cục bộ (codeIndex)
        // Chúng ta cần một index toàn cục cho hàm displayResults
        let globalCodeIndex = 0;
        contentProcessedHTML = contentProcessedHTML.replace(/@@CODE@@/g, () => {
             const block = codeBlocksHTML[globalCodeIndex] || '';
             globalCodeIndex++;
             return block;
        });

         // Hiển thị các code block còn lại nếu số placeholder ít hơn số snippet
         if (globalCodeIndex < codeBlocksHTML.length) {
             contentProcessedHTML += codeBlocksHTML.slice(globalCodeIndex).join('');
         }


    } // Kết thúc if (item.content)
    // Nếu không có content, vẫn hiển thị code snippets
    else if (codeBlocksHTML.length > 0){
        contentProcessedHTML = codeBlocksHTML.join('');
    }

    cardHTML += `<div class="content-snippet">${contentProcessedHTML}</div>`;


    // 4. Tags và Source (Giữ nguyên)
    if (item.tags && Array.isArray(item.tags) && item.tags.length > 0) {
      cardHTML += `<div class="tags">Tags: ${item.tags.map(tag => `<span class="tag">${escapeHTML(tag)}</span>`).join(' ')}</div>`;
    }
    if (item.related_cves && Array.isArray(item.related_cves) && item.related_cves.length > 0) {
        cardHTML += `<div class="tags">CVEs: ${item.related_cves.map(cve => `<span class="tag cve">${escapeHTML(cve)}</span>`).join(' ')}</div>`;
    }
    cardHTML += `<p class="source-file">Source: ${escapeHTML(item.source_file || 'N/A')}</p>`;

    resultCard.innerHTML = cardHTML;
    resultsContainer.appendChild(resultCard);
  });
}

// ... (Phần còn lại của script.js giữ nguyên) ...
/* ================================================================= */
/* === PHẦN 2: LOGIC KHUNG ỨNG DỤNG === */
/* ================================================================= */

let unifiedPlaybookKeywords = [];
let playbookSearchableTermsCache = {};
let appState;
let noteEditor; // Khai báo noteEditor ở scope cao hơn

// Debounce function (giữ nguyên)
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func.apply(this, args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

document.addEventListener('DOMContentLoaded', () => {
  // ========== 1. DOM ELEMENTS ==========
  // Nút Clear
  const clearMainSearchBtn = document.getElementById('clear-main-search-btn');
  const clearPlaybookSearchBtn = document.getElementById('clear-playbook-search-btn');
  // Nút Copy IP
  const copyKaliIpBtn = document.getElementById('copy-kali-ip-btn');
  const searchInput = document.getElementById('searchInput');
  const targetListInput = document.getElementById('targetListInput');
  const targetSelectorContainer = document.getElementById('targetSelectorContainer');
  const resultsContainer = document.getElementById('results');
  const bookmarkBtn = document.getElementById('bookmarkBtn');
  const searchBtn = document.getElementById('searchBtn');
  const themeToggle = document.getElementById('theme-toggle');
  const getKaliIpBtn = document.getElementById('get-kali-ip');
  const myKaliIpDisplay = document.getElementById('my-kali-ip-display');
  const langViBtn = document.getElementById('lang-vi');
  const langEnBtn = document.getElementById('lang-en');
  const noteTakingArea = document.getElementById('note-taking-area');
  const noteTitle = document.getElementById('note-title');
  const noteContentTextarea = document.getElementById('note-content'); // Vẫn lấy element ở đây
  const downloadNoteBtn = document.getElementById('download-note-btn');
  const projectSelector = document.getElementById('project-selector');
  const newProjectBtn = document.getElementById('new-project-btn');
  const playbookSearchInput = document.getElementById('playbook-search-input');
  const playbookSuggestionBox = document.getElementById('playbook-suggestion-box');
  const playbookSelectedTags = document.getElementById('playbook-selected-tags');
  const playbookResults = document.getElementById('playbook-results');

  const ipColorCache = {};

  // Hàm helper load localStorage (giữ nguyên)
  const loadFromLocalStorage = (key, defaultValue) => { /* ... giữ nguyên ... */
      try {
          const item = localStorage.getItem(key);
          return item ? JSON.parse(item) : defaultValue;
      } catch (error) {
          console.error(`Error parsing localStorage key "${key}":`, error);
          localStorage.removeItem(key);
          return defaultValue;
      }
  };

  // ========== 2. APPLICATION STATE ==========
  appState = { /* ... giữ nguyên ... */
    projects: loadFromLocalStorage('sch_projects', ['Default Project']),
    activeProject: localStorage.getItem('sch_activeProject') || 'Default Project',
    bookmarks: [],
    currentView: 'search',
    selectedTarget: null,
    currentLang: localStorage.getItem('sch_lang') || 'vi',
    currentTheme: localStorage.getItem('sch_theme') || 'light',
    playbookSearchTags: []
  };

   // ========== 3. CORE FUNCTIONS (Logic chung) ==========
   // (stringToHslColor, getIpColor, populateProjectSelector, switchProject, createNewProject giữ nguyên)
   /* ... các hàm này giữ nguyên ... */
    const stringToHslColor = (str, s, l) => { let hash = 0; for (let i = 0; i < str.length; i++) { hash = str.charCodeAt(i) + ((hash << 5) - hash); } const h = hash % 360; return `hsl(${h}, ${s}%, ${l}%)`; };
    const getIpColor = (ip) => { if (!ipColorCache[ip]) { ipColorCache[ip] = stringToHslColor(ip, 70, 45); } return ipColorCache[ip]; };
    const populateProjectSelector = () => { projectSelector.innerHTML = ''; appState.projects.forEach(proj => { const option = document.createElement('option'); option.value = proj; option.textContent = proj; if (proj === appState.activeProject) option.selected = true; projectSelector.appendChild(option); }); };
    const switchProject = (projectName) => { appState.activeProject = projectName; localStorage.setItem('sch_activeProject', projectName); loadProjectData(); populateProjectSelector(); };
    const createNewProject = () => { const projectName = prompt(translations[appState.currentLang]?.promptNewProject || translations['en']?.promptNewProject); if (projectName && projectName.trim() !== '' && !appState.projects.includes(projectName.trim())) { const trimmedName = projectName.trim(); appState.projects.push(trimmedName); localStorage.setItem('sch_projects', JSON.stringify(appState.projects)); switchProject(trimmedName); } else if (projectName && appState.projects.includes(projectName.trim())) { alert("Project name already exists!"); } };


  const loadProjectData = () => { /* ... giữ nguyên ... */
    const projectKey = appState.activeProject;
    appState.bookmarks = loadFromLocalStorage(`sch_${projectKey}_bookmarks`, []);
    targetListInput.value = localStorage.getItem(`sch_${projectKey}_target_ips`) || '';
    appState.playbookSearchTags = loadFromLocalStorage(`sch_${projectKey}_playbook_tags`, []);
    generateTargetSelectors();
    updateActiveNavButton();
    renderSelectedPlaybookTags();
    findRecommendedPlaybook();
  };

  const setLanguage = (lang) => { /* ... giữ nguyên, đã có fallback ... */
    appState.currentLang = lang;
    localStorage.setItem('sch_lang', lang);
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-translate], [data-translate-placeholder], [data-translate-title]').forEach(el => {
      const key = el.dataset.translate || el.dataset.translatePlaceholder || el.dataset.translateTitle;
      const translation = translations[lang]?.[key] || translations['en']?.[key]; // Lấy bản dịch, fallback về 'en'
      if (translation) {
        if (el.dataset.translate) el.textContent = translation;
        else if (el.dataset.translatePlaceholder) el.placeholder = translation;
        else if (el.dataset.translateTitle) el.title = translation;
      }
    });
    langViBtn.classList.toggle('active', lang === 'vi');
    langEnBtn.classList.toggle('active', lang === 'en');
    findRecommendedPlaybook();
    updateActiveNavButton();
    if (appState.selectedTarget) updateNoteArea(appState.selectedTarget);
    renderSelectedPlaybookTags();
    document.querySelectorAll('.copy-btn').forEach(btn => {
      if (!(btn.textContent === (translations[lang]?.copied || 'Copied!'))) {
        btn.textContent = translations[lang]?.copy || 'Copy';
      }
    });
    // Cập nhật thông báo IP
    const ipFoundTextVi = translations['vi']?.ipFound;
    const ipFoundTextEn = translations['en']?.ipFound;
    const gettingIPTextVi = translations['vi']?.gettingIP;
    const gettingIPTextEn = translations['en']?.gettingIP;
    const ipNotFoundTextVi = translations['vi']?.ipNotFound;
    const ipNotFoundTextEn = translations['en']?.ipNotFound;

    if (kaliIpInput.value.includes(ipFoundTextVi) || kaliIpInput.value.includes(ipFoundTextEn)) {
        const currentIp = kaliIpInput.value.split(': ')[1];
        if (currentIp) {
            kaliIpInput.value = `${translations[appState.currentLang].ipFound} ${currentIp}`;
        }
    } else if (kaliIpInput.value.includes(gettingIPTextVi) || kaliIpInput.value.includes(gettingIPTextEn)) {
        kaliIpInput.value = translations[appState.currentLang].gettingIP;
    } else if (kaliIpInput.value.includes(ipNotFoundTextVi) || kaliIpInput.value.includes(ipNotFoundTextEn)) {
        kaliIpInput.value = translations[appState.currentLang].ipNotFound;
    }

    // Cập nhật thông báo kết quả/bookmark
    if (resultsContainer.querySelector('p')) {
        const pElement = resultsContainer.querySelector('p');
        const initialMsgVi = translations['vi']?.initialMessage;
        const initialMsgEn = translations['en']?.initialMessage;
        const noResultsMsgVi = translations['vi']?.noResults;
        const noResultsMsgEn = translations['en']?.noResults;
        const noBookmarksMsgVi = translations['vi']?.noBookmarks;
        const noBookmarksMsgEn = translations['en']?.noBookmarks;

        if (pElement.textContent === initialMsgVi || pElement.textContent === initialMsgEn) {
            pElement.textContent = translations[appState.currentLang].initialMessage;
        } else if (pElement.textContent === noResultsMsgVi || pElement.textContent === noResultsMsgEn) {
            pElement.textContent = translations[appState.currentLang].noResults;
        } else if (pElement.textContent === noBookmarksMsgVi || pElement.textContent === noBookmarksMsgEn) {
            pElement.textContent = translations[appState.currentLang].noBookmarks;
        }
    }
  };

  const applyTheme = (theme) => { /* ... giữ nguyên ... */
    document.documentElement.setAttribute('data-theme', theme);
    appState.currentTheme = theme;
    localStorage.setItem('sch_theme', theme);
    document.getElementById('theme-icon-sun').style.display = theme === 'light' ? 'block' : 'none';
    document.getElementById('theme-icon-moon').style.display = theme === 'dark' ? 'block' : 'none';
     if (noteEditor) {
        noteEditor.setOption('theme', 'material-darker'); // Luôn dùng theme tối cho editor
    }
  };
  const toggleTheme = () => applyTheme(appState.currentTheme === 'light' ? 'dark' : 'light');

  // Logic IP (getLocalIP, handleGetKaliIP) giữ nguyên
  /* ... getLocalIP, handleGetKaliIP giữ nguyên ... */
//   const getLocalIP = () => {
//     return new Promise((resolve) => {
//       let ips = { preferred: null, candidates: [] };
//       try {
//         window.RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
//         const pc = new RTCPeerConnection({ iceServers: [] });
//         const noop = function(){};
//         pc.createDataChannel("");
//         pc.createOffer(pc.setLocalDescription.bind(pc), noop);
//         pc.onicecandidate = function(ice){
//           if(!ice || !ice.candidate || !ice.candidate.candidate) return;
//           const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/i;
//           const match = ipRegex.exec(ice.candidate.candidate);
//           const ip = match ? match[1] : null;
//           if (ip) {
//              if (ip !== '0.0.0.0' && ip !== '::1' && !ip.startsWith('127.') && !ip.startsWith('169.254.') && !ips.candidates.includes(ip)) {
//                 ips.candidates.push(ip);
//              }
//           }
//         };
//         setTimeout(() => {
//           pc.close();
//           if (ips.candidates.length > 0) {
//             const ipPriority = (ip) => {
//                 if (ip.startsWith('192.168.')) return 1;
//                 if (ip.startsWith('10.')) return 2;
//                 if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return 3;
//                 if (/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(ip)) return 4;
//                 if (ip.includes(':')) return 6;
//                 return 99;
//             };
//             ips.candidates.sort((a, b) => ipPriority(a) - ipPriority(b));
//             ips.candidates = ips.candidates.filter(ip => ipPriority(ip) <= 6);
//             ips.preferred = ips.candidates.length > 0 ? ips.candidates[0] : null;
//           }
//           resolve(ips);
//         }, 700);
//       } catch (e) {
//         console.error("WebRTC Error:", e);
//         resolve(ips);
//       }
//     });
//   };



//   const handleGetKaliIP = async () => {
//     kaliIpInput.value = translations[appState.currentLang]?.gettingIP || 'Getting IP...';
//     myKaliIpDisplay.style.display = 'block';
//     getKaliIpBtn.disabled = true;
//     myKaliIpDisplay.style.color = 'var(--text-secondary)';
//     kaliIpInput.value = translations[appState.currentLang]?.gettingIP || 'Getting IP...';
//     myKaliIpDisplay.style.display = 'block'; // Hiển thị text loading
//     copyKaliIpBtn.style.display = 'none'; // Ẩn nút copy khi đang load
//     try {
//       const ipResult = await getLocalIP();
//       if (ipResult.preferred) {
          
//           kaliIpInput.value = ipResult.preferred; // Chỉ gán địa chỉ IP
//           myKaliIpDisplay.style.color = 'var(--accent-color)';
//           copyKaliIpBtn.style.display = 'inline-flex'; // *** HIỂN THỊ NÚT COPY ***
//           copyKaliIpBtn.classList.remove('copied');
//           if (ipResult.candidates.length > 1) {
//               const otherIPs = ipResult.candidates.slice(1).join(', ');
//               myKaliIpDisplay.title = `Other IPs found: ${otherIPs}`;
//               console.log("Other IPs found:", ipResult.candidates.slice(1));
//           } else {
//               myKaliIpDisplay.title = '';
//           }
//       } else if (ipResult.candidates.length > 0) {
//            kaliIpInput.value = `Found: ${ipResult.candidates[0]} (Check others?)`;
//            myKaliIpDisplay.style.color = 'orange';
//            copyKaliIpBtn.style.display = 'none'; // *** ẨN NÚT COPY ***
//            myKaliIpDisplay.title = `All IPs found: ${ipResult.candidates.join(', ')}`;
//            console.log("All IPs found:", ipResult.candidates);
//            if (appState.currentView === 'search') handleSearch(); else showBookmarks();
//       }
//       else {
//           kaliIpInput.value = translations[appState.currentLang]?.ipNotFound || 'Local IP not found.';
//           myKaliIpDisplay.style.color = 'red';
//           copyKaliIpBtn.style.display = 'none'; // *** ẨN NÚT COPY ***
//           myKaliIpDisplay.title = '';
//           if (appState.currentView === 'search') handleSearch(); else showBookmarks();
//       }
//     } catch (error) {
//       console.error("Error getting IP:", error);
//       kaliIpInput.value = "Error getting IP.";
//       myKaliIpDisplay.style.color = 'red';
//       myKaliIpDisplay.title = '';
//       copyKaliIpBtn.style.display = 'none'; // *** ẨN NÚT COPY KHI LỖI ***
//        if (appState.currentView === 'search') handleSearch(); else showBookmarks();
//     } finally {
//       getKaliIpBtn.disabled = false;
//     }
//   };


const kaliIpInput = document.getElementById('kali-ip-input'); // Thay đổi

  // *** SỬA LỖI: Logic Ghi chú (Khởi tạo trì hoãn) ***
  const initializeNoteEditor = () => {
    // Chỉ khởi tạo nếu chưa có VÀ thẻ tồn tại
    if (!noteEditor && noteContentTextarea) {
        try {
            noteEditor = CodeMirror.fromTextArea(noteContentTextarea, {
              lineNumbers: true,
              mode: 'markdown',
              theme: 'material-darker', // Luôn dùng theme tối
              lineWrapping: true
            });
            const debouncedSave = debounce(saveNote, 750);
            noteEditor.on('change', debouncedSave);
            console.log("CodeMirror Initialized Successfully"); // Log thành công
        } catch (e) {
            console.error("Failed to initialize CodeMirror:", e);
            // Fallback: Hiện textarea gốc CHỈ KHI CM lỗi
            if (noteContentTextarea) {
               noteContentTextarea.style.display = 'block';
               // Thêm class để CSS biết CM lỗi (tùy chọn)
               noteTakingArea.classList.add('codemirror-failed');
            }
        }
    } else if (!noteContentTextarea) {
         console.error("Error: Textarea element with id='note-content' not found!");
    } else {
        // console.log("CodeMirror already initialized."); // Debug log
    }
  };

  const updateNoteArea = (ip) => {
    document.querySelectorAll('#targetSelectorContainer label').forEach(lbl => lbl.classList.remove('active'));
    noteTakingArea.classList.remove('active');
    const statusElement = document.getElementById('note-save-status');
    if (statusElement) {
        statusElement.textContent = "";
        statusElement.className = 'note-status';
        statusElement.style.opacity = '0';
    }

    if (!ip) {
      noteTakingArea.style.display = 'none'; // Ẩn widget
      appState.selectedTarget = null;
      return;
    }

    // --- Bắt đầu cập nhật ---
    appState.selectedTarget = ip;
    const ipColor = getIpColor(ip);
    noteTakingArea.style.setProperty('--ip-color', ipColor);
    const activeLabel = document.querySelector(`input[name="target-ip-option"][value="${CSS.escape(ip)}"]`)?.closest('label');
    if (activeLabel) activeLabel.classList.add('active');

    // 1. Hiển thị Widget TRƯỚC
    noteTakingArea.style.display = 'block';
    noteTakingArea.classList.add('active');
    noteTitle.textContent = `${translations[appState.currentLang]?.notesFor || 'Notes for'} ${ip}`;

    const noteKey = `sch_${appState.activeProject}_note_${ip.replace(/\./g, '_')}`;
    const content = localStorage.getItem(noteKey) || ``;

    // 2. Gọi hàm khởi tạo (nó sẽ tự kiểm tra nếu đã tạo rồi)
    initializeNoteEditor();

    // 3. Cập nhật nội dung VÀ Refresh SAU KHI hiển thị (nếu editor đã sẵn sàng)
    if (noteEditor) {
        // Chỉ set giá trị nếu nội dung khác
        if (noteEditor.getValue() !== content) {
            noteEditor.setValue(content);
        }
        // Gọi refresh trong setTimeout
        setTimeout(() => {
            if (noteEditor && noteTakingArea.offsetParent !== null) { // Chỉ refresh nếu widget thực sự hiển thị
                // console.log("Refreshing CodeMirror for IP:", ip);
                try {
                    noteEditor.refresh();
                } catch(e) {
                    console.error("Error refreshing CodeMirror:", e);
                }
                // noteEditor.scrollTo(0, 0); // Cuộn lên đầu
            }
        }, 50); // Cho trình duyệt thời gian render
    } else if (noteContentTextarea) { // Fallback nếu editor không khởi tạo được
        noteContentTextarea.value = content;
        noteContentTextarea.style.display = 'block'; // Đảm bảo textarea gốc hiển thị
    }
  };

  const saveNote = () => { /* ... giữ nguyên ... */
    const statusElement = document.getElementById('note-save-status');
    if (appState.selectedTarget && noteEditor) {
      const noteKey = `sch_${appState.activeProject}_note_${appState.selectedTarget.replace(/\./g, '_')}`;
      const currentContent = noteEditor.getValue();
      if (statusElement) {
          statusElement.textContent = translations[appState.currentLang]?.savingStatus || "Saving...";
          statusElement.className = 'note-status saving';
          statusElement.style.opacity = '1'; // Hiện status
      }
      try {
          if (localStorage.getItem(noteKey) !== currentContent) {
             localStorage.setItem(noteKey, currentContent);
          }
          if (statusElement) {
              statusElement.textContent = translations[appState.currentLang]?.savedStatus || "Saved";
              statusElement.className = 'note-status saved';
              setTimeout(() => {
                  if (statusElement.classList.contains('saved')) {
                     statusElement.textContent = "";
                     statusElement.className = 'note-status';
                     statusElement.style.opacity = '0';
                  }
              }, 2000);
          }
      } catch (error) {
          console.error("Failed to save note:", error);
           if (statusElement) {
              statusElement.textContent = translations[appState.currentLang]?.errorStatus || "Error saving!";
              statusElement.className = 'note-status error';
           }
      }
    } else if (statusElement) {
         statusElement.textContent = "";
         statusElement.className = 'note-status';
         statusElement.style.opacity = '0';
    }
  };

  const downloadNote = () => { /* ... giữ nguyên ... */
    if (!appState.selectedTarget) return;
    let contentToDownload = '';
    if (noteEditor) {
        contentToDownload = noteEditor.getValue();
    } else if (noteContentTextarea){ // Thêm kiểm tra noteContentTextarea
        contentToDownload = noteContentTextarea.value;
    }
    if (!contentToDownload && !confirm("Note is empty. Do you want to download an empty file?")) {
         return;
     }
    const blob = new Blob([contentToDownload], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const safeIp = appState.selectedTarget.replace(/[^a-zA-Z0-9._-]/g, '_');
    a.download = `log-${safeIp}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // ========== 4. LOGIC TÌM KIẾM CHÍNH (Fuse.js) ==========
  // (handleSearch, showBookmarks, toggleBookmark, updateActiveNavButton giữ nguyên)
  /* ... các hàm này giữ nguyên ... */
const handleSearch = () => {
    if (appState.currentView !== 'search') {
        resultsContainer.innerHTML = '';
        return;
    }
    const query = searchInput.value.trim();
    const targetIP = appState.selectedTarget;

    // *** THAY ĐỔI CÁCH LẤY KALI IP ***
    let kaliIP = '';
    kaliIP = kaliIpInput.value.trim();
    // Kiểm tra xem nội dung có phải là IP không (không phải là trạng thái loading/error)
    // Regex đơn giản để kiểm tra định dạng IP (có thể cải thiện nếu cần IPv6)
    // if (kaliIpDisplayText && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(kaliIpDisplayText.trim())) {
    //     kaliIP = kaliIpDisplayText.trim();
    // }
    // *** KẾT THÚC THAY ĐỔI ***

    // Hiện/ẩn nút clear (giữ nguyên)
    if (clearMainSearchBtn) {
        clearMainSearchBtn.style.display = query ? 'flex' : 'none';
    }

    // Logic tìm kiếm và hiển thị (giữ nguyên)
    if (query && query.length >= 2) {
      const results = fuse.search(query);
      displayResults(results, targetIP, kaliIP); // Truyền kaliIP đã lấy được
    } else if (query.length > 0 && query.length < 2) {
        resultsContainer.innerHTML = `<p style="text-align: center;">${translations[appState.currentLang]?.searchHint || 'Enter at least 2 characters.'}</p>`;
    } else {
      resultsContainer.innerHTML = `<p style="text-align: center;">${translations[appState.currentLang]?.initialMessage || 'Enter a keyword...'}</p>`;
    }
  };
 const showBookmarks = () => {
    const targetIP = appState.selectedTarget;

    // *** THAY ĐỔI CÁCH LẤY KALI IP (Giống handleSearch) ***
    let kaliIP = '';
    const kaliIpDisplayText = kaliIpInput.value;
    if (kaliIpDisplayText && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(kaliIpDisplayText.trim())) {
        kaliIP = kaliIpDisplayText.trim();
    }
    // *** KẾT THÚC THAY ĐỔI ***

    // Logic lấy bookmark (giữ nguyên)
    const bookmarkedItems = appState.bookmarks.map(key => {
        const item = knowledgeDataMap[key];
        return item ? { item: item } : null;
    }).filter(Boolean);

    displayResults(bookmarkedItems, targetIP, kaliIP); // Truyền kaliIP đã lấy được
  };
  const toggleBookmark = (topicKey, button) => {
    const index = appState.bookmarks.indexOf(topicKey);
    let isBookmarkedNow = false;
    if (index > -1) {
        appState.bookmarks.splice(index, 1);
        button.classList.remove('bookmarked');
        isBookmarkedNow = false;
    } else {
        appState.bookmarks.push(topicKey);
        button.classList.add('bookmarked');
        isBookmarkedNow = true;
    }
    try {
        localStorage.setItem(`sch_${appState.activeProject}_bookmarks`, JSON.stringify(appState.bookmarks));
    } catch (error) {
        console.error("Failed to save bookmarks to localStorage:", error);
        if (isBookmarkedNow) { appState.bookmarks.pop(); button.classList.remove('bookmarked'); }
        alert("Error saving bookmark state.");
        return;
    }
    if (appState.currentView === 'bookmarks') { showBookmarks(); }
  };
  const updateActiveNavButton = () => {
    searchBtn.classList.toggle('active', appState.currentView === 'search');
    bookmarkBtn.classList.toggle('active', appState.currentView === 'bookmarks');
    if (appState.currentView === 'search') {
        searchInput.style.display = 'block';
        handleSearch();
    } else {
        searchInput.style.display = 'none';
        showBookmarks();
    }
  };


  // ========== 5. LOGIC TÌM KIẾM PLAYBOOK (MỚI) ==========
  // (createPlaybookData, renderPlaybookSuggestions, renderSelectedPlaybookTags, findRecommendedPlaybook giữ nguyên)
  /* ... các hàm này giữ nguyên ... */
    const createPlaybookData = () => { const allKeywords = new Set(); playbookSearchableTermsCache = {}; const techToPlaybooks = {}; Object.keys(TECHNOLOGIES).forEach(techKey => { allKeywords.add(techKey); const tech = TECHNOLOGIES[techKey]; if (tech && Array.isArray(tech.playbooks)) { tech.playbooks.forEach(playbookId => { if (!techToPlaybooks[playbookId]) { techToPlaybooks[playbookId] = new Set(); } techToPlaybooks[playbookId].add(techKey); }); } }); Object.keys(PLAYBOOKS).forEach(playbookId => { const playbook = PLAYBOOKS[playbookId]; const searchableTerms = new Set(playbook.tags || []); if (techToPlaybooks[playbookId]) { techToPlaybooks[playbookId].forEach(techKey => searchableTerms.add(techKey)); } (playbook.tags || []).forEach(tag => allKeywords.add(tag)); playbookSearchableTermsCache[playbookId] = searchableTerms; }); unifiedPlaybookKeywords = [...allKeywords].sort(); };
    const renderPlaybookSuggestions = (query) => { playbookSuggestionBox.innerHTML = ''; if (!query) { playbookSuggestionBox.style.display = 'none'; return; } const lowerQuery = query.toLowerCase(); const matches = unifiedPlaybookKeywords.filter(k => k.toLowerCase().includes(lowerQuery) && !appState.playbookSearchTags.includes(k)).slice(0, 10); if (matches.length === 0) { playbookSuggestionBox.style.display = 'none'; return; } let suggestionsHTML = ''; const regex = new RegExp(query.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'), 'gi'); matches.forEach(match => { const highlightedMatch = match.replace(regex, (m) => `<mark>${m}</mark>`); suggestionsHTML += `<div class="suggestion-item" data-keyword="${escapeHTML(match)}">${highlightedMatch}</div>`; }); playbookSuggestionBox.innerHTML = suggestionsHTML; playbookSuggestionBox.style.display = 'block'; };
    const renderSelectedPlaybookTags = () => { playbookSelectedTags.innerHTML = ''; if (appState.playbookSearchTags.length === 0) { playbookSelectedTags.innerHTML = `<span class="no-tags-msg" data-translate="playbookInitial">${translations[appState.currentLang]?.playbookInitial || translations['en']?.playbookInitial}</span>`; return; } let tagsHTML = ''; appState.playbookSearchTags.forEach(tag => { const techInfo = TECHNOLOGIES[tag]; const techTitle = techInfo?.title?.[appState.currentLang] || techInfo?.title?.['en'] || tag; tagsHTML += ` <div class="tag-pill"> <span>${escapeHTML(techTitle)}</span> <button class="remove-tag-btn" data-keyword="${escapeHTML(tag)}" aria-label="Remove tag ${escapeHTML(techTitle)}">&times;</button> </div> `; }); playbookSelectedTags.innerHTML = tagsHTML; };
    const findRecommendedPlaybook = () => { const selectedTags = appState.playbookSearchTags; playbookResults.innerHTML = ''; if (selectedTags.length === 0) { return; } const scores = {}; Object.keys(playbookSearchableTermsCache).forEach(playbookKey => { const searchableTerms = playbookSearchableTermsCache[playbookKey]; let currentScore = 0; selectedTags.forEach(tag => { if (searchableTerms.has(tag)) { currentScore++; } }); if (currentScore > 0) { scores[playbookKey] = currentScore; } }); const sortedPlaybookKeys = Object.keys(scores).sort((a, b) => scores[b] - scores[a]); if (sortedPlaybookKeys.length === 0) { playbookResults.innerHTML = `<p>${translations[appState.currentLang]?.noResults || translations['en']?.noResults}</p>`; } else { sortedPlaybookKeys.forEach(playbookKey => { const playbook = PLAYBOOKS[playbookKey]; if (playbook) { const card = createPlaybookCard(playbook, playbookKey); if (card) { playbookResults.appendChild(card); } } else { console.warn(`Playbook with key "${playbookKey}" not found in PLAYBOOKS data.`); } }); } };


  // *** ĐÂY LÀ PHIÊN BẢN ĐÚNG CỦA createPlaybookCard (sử dụng steps) ***
// *** THAY THẾ TOÀN BỘ HÀM NÀY (Bắt đầu từ dòng 598) ***
  const createPlaybookCard = (playbook, key) => {
    if (!playbook) return null; // Thêm kiểm tra an toàn

    const lang = appState.currentLang;
    const targetIP = appState.selectedTarget;

    // Lấy Kali IP (chỉ lấy nếu là IP)
    let kaliIP = '';
    // const kaliIpDisplayText = kaliIpInput.value;
    // if (kaliIpDisplayText && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(kaliIpDisplayText.trim())) {
    //     kaliIP = kaliIpDisplayText.trim();
    // }
    kaliIP = kaliIpInput.value.trim();
    const card = document.createElement('div');
    card.className = 'playbook-card';
    card.dataset.key = key;

    // Lấy title (Giữ nguyên)
    const playbookTitle = playbook.title?.[lang] || playbook.title?.['en'] || key;

    // *** BỔ SUNG LOGIC LẤY ASSUMPTION (PHẦN BỊ THIẾU) ***
    let assumptionHTML = '';
    // Lấy assumption, ưu tiên ngôn ngữ, fallback về 'en' hoặc text gốc
    const assumptionText = playbook.assumption?.[lang] || playbook.assumption?.['en'] || playbook.assumption;
    if (assumptionText) {
        // Sử dụng key dịch 'assumptionLabel' từ data.js
        assumptionHTML = `<p class="playbook-assumption"><strong>${translations[lang]?.assumptionLabel || 'Assumption:'}</strong> ${escapeHTML(assumptionText)}</p>`;
    }


   // *** XỬ LÝ TRƯỜNG CONTENT ĐỂ HIỂN THỊ ĐẸP HƠN ***
    let contentFormattedHTML = '';
    const contentTextRaw = playbook.content?.[lang] || playbook.content?.['en'] || playbook.content; // Lấy content thô

    if (contentTextRaw) {
        let processedContent = escapeHTML(contentTextRaw); // Escape trước

        // Thay thế IP placeholders (nếu cần, nhưng có vẻ content không dùng)
        if (targetIP) processedContent = processedContent.replace(/<target_ip>|\[TARGET_IP\]/g, targetIP);
        if (kaliIP) processedContent = processedContent.replace(/<kali_ip>|\[KALI_IP\]/g, kaliIP);

        // Chuyển đổi Markdown cơ bản sang HTML
        processedContent = processedContent
            .replace(/^## (.*$)/gm, '<h5>$1</h5>') // Chuyển ## thành <h5>
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') // Chuyển **bold** thành <strong>
            .replace(/`([^`]+)`/g, '<code>$1</code>'); // Chuyển `code` thành <code>

        // Xử lý list item (ul và ol)
        const lines = processedContent.split('\n'); // Tách theo dòng mới gốc
        let listHTML = '';
        let currentListType = null; // null, 'ul', 'ol'

        lines.forEach(line => {
            const trimmedLine = line.trim();
            const ulMatch = trimmedLine.match(/^(?:&lowast;|\*|-)\s+(.*)/); // Match *, -, &lowast;
            const olMatch = trimmedLine.match(/^(\d+)\.\s+(.*)/); // Match 1., 2.

            if (ulMatch) {
                if (currentListType !== 'ul') {
                    if (currentListType) listHTML += `</${currentListType}>`; // Đóng list cũ nếu có
                    listHTML += '<ul>';
                    currentListType = 'ul';
                }
                listHTML += `<li>${ulMatch[1]}</li>`; // Nội dung đã được escape
            } else if (olMatch) {
                if (currentListType !== 'ol') {
                    if (currentListType) listHTML += `</${currentListType}>`; // Đóng list cũ nếu có
                    listHTML += '<ol>';
                    currentListType = 'ol';
                }
                listHTML += `<li>${olMatch[2]}</li>`; // Nội dung đã được escape
            } else {
                if (currentListType) {
                    listHTML += `</${currentListType}>`; // Đóng list khi gặp dòng không phải list item
                    currentListType = null;
                }
                // Xử lý các dòng không phải list (ví dụ: tiêu đề h5 đã chuyển đổi)
                // Chỉ thêm nếu dòng không trống
                if (trimmedLine) {
                   // Bọc dòng bằng <p> nếu nó không phải là tag HTML đã xử lý (h5)
                   if (!trimmedLine.startsWith('<h5')) {
                       listHTML += `<p>${line}</p>`; // Giữ lại line gốc đã escape và xử lý bold/code
                   } else {
                       listHTML += line; // Thêm h5 trực tiếp
                   }
                }
            }
        });

        if (currentListType) {
            listHTML += `</${currentListType}>`; // Đóng list cuối cùng nếu có
        }
        contentFormattedHTML = `<div class="playbook-content-formatted">${listHTML}</div>`; // Bọc trong div để dễ style
    }


    // *** KẾT THÚC BỔ SUNG ***

    // Tạo HTML cho steps (Giữ nguyên logic cũ của bạn)
    let stepsHTML = '';
    if (playbook.steps && Array.isArray(playbook.steps) && playbook.steps.length > 0) {
        stepsHTML += '<ol>';
        playbook.steps.forEach((step, index) => {
          if (step) {
              const stepText = step[lang] || step['en'] || `(Missing step text ${index + 1})`;
              stepsHTML += `<li><p>${escapeHTML(stepText)}</p>`;

              // Thêm notes (nếu có)
              if(step.notes && (step.notes[lang] || step.notes['en'])){
                  stepsHTML += `<p><em>(${escapeHTML(step.notes[lang] || step.notes['en'])})</em></p>`;
              }

              if (step.command) {
                let command = step.command;
                if (targetIP) command = command.replace(/\[TARGET_IP\]/g, targetIP);
                if (kaliIP) command = command.replace(/\[KALI_IP\]/g, kaliIP);
                const escapedCommand = escapeHTML(command);
                const langClass = step.language ? `language-${escapeHTML(step.language)}` : 'language-bash';
                stepsHTML += `<pre><code class="${langClass}">${escapedCommand}</code><button class="copy-btn" onclick="copyCode(this)">${translations[lang]?.copy || 'Copy'}</button></pre>`;
              }
              stepsHTML += `</li>`;
          }
        });
        stepsHTML += '</ol>';
    } else {
        stepsHTML = `<p>(${translations[lang]?.noStepsAvailable || translations['en']?.noStepsAvailable || 'No steps available'})</p>`;
    }

    // Tạo HTML cho tags (Giữ nguyên)
    const tagsHTML = (playbook.tags && Array.isArray(playbook.tags) ? playbook.tags : [])
        .map(tag => `<span class="playbook-tag">${escapeHTML(tag)}</span>`).join('');

    // *** CẬP NHẬT card.innerHTML ĐỂ BAO GỒM assumptionHTML ***
    card.innerHTML = `
            <div class="playbook-card-content">
                <h4>${escapeHTML(playbookTitle)}</h4>
                ${assumptionHTML} 
                ${contentFormattedHTML}
                ${stepsHTML}
                <div class="playbook-tags">${tagsHTML}</div>
            </div>`;
    return card;
  };
  // *** KẾT THÚC HÀM THAY THẾ ***

  // ========== 6. EVENT HANDLERS ==========
  // (generateTargetSelectors, initEventListeners, addPlaybookTag, removePlaybookTag, savePlaybookTags giữ nguyên)
  /* ... các hàm này giữ nguyên ... */
  const generateTargetSelectors = () => { const ipsRaw = targetListInput.value.split('\n'); const ipsFiltered = ipsRaw.map(ip => ip.trim()).filter(ip => ip !== '' && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)); localStorage.setItem(`sch_${appState.activeProject}_target_ips`, targetListInput.value); targetSelectorContainer.innerHTML = ''; let currentSelectedFound = false; if (ipsFiltered.length > 0) { ipsFiltered.forEach((ip, index) => { const label = document.createElement('label'); const ipColor = getIpColor(ip); label.style.setProperty('--ip-color', ipColor); const radio = document.createElement('input'); radio.type = 'radio'; radio.name = 'target-ip-option'; radio.value = ip; radio.id = `ip-option-${index}`; if (appState.selectedTarget === ip) { radio.checked = true; currentSelectedFound = true; label.classList.add('active'); } const span = document.createElement('span'); span.textContent = ip; const deleteBtn = document.createElement('button'); deleteBtn.className = 'delete-ip-btn'; deleteBtn.dataset.ip = ip; deleteBtn.setAttribute('aria-label', `Delete IP ${ip}`); deleteBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>`; label.appendChild(radio); label.appendChild(span); label.appendChild(deleteBtn); targetSelectorContainer.appendChild(label); }); if (!currentSelectedFound && ipsFiltered.length > 0) { appState.selectedTarget = ipsFiltered[0]; const firstRadio = targetSelectorContainer.querySelector('input[type="radio"]'); if (firstRadio) { firstRadio.checked = true; firstRadio.closest('label')?.classList.add('active'); } } else if (ipsFiltered.length === 0) { appState.selectedTarget = null; } } else { appState.selectedTarget = null; } if (appState.currentView === 'search') handleSearch(); else showBookmarks(); updateNoteArea(appState.selectedTarget); };
  const initEventListeners = () => { themeToggle.addEventListener('click', toggleTheme);  langViBtn.addEventListener('click', () => setLanguage('vi')); langEnBtn.addEventListener('click', () => setLanguage('en')); newProjectBtn.addEventListener('click', createNewProject); projectSelector.addEventListener('change', (e) => switchProject(e.target.value)); downloadNoteBtn.addEventListener('click', downloadNote); searchInput.addEventListener('input', handleSearch); searchBtn.addEventListener('click', () => { if (appState.currentView !== 'search') { appState.currentView = 'search'; updateActiveNavButton(); } }); bookmarkBtn.addEventListener('click', () => { if (appState.currentView !== 'bookmarks') { appState.currentView = 'bookmarks'; updateActiveNavButton(); } }); resultsContainer.addEventListener('click', (e) => { const bookmarkButton = e.target.closest('.bookmark-toggle-btn'); if (bookmarkButton) { const key = bookmarkButton.dataset.key; if (key) { toggleBookmark(key, bookmarkButton); } } }); targetListInput.addEventListener('input', generateTargetSelectors); targetSelectorContainer.addEventListener('change', (e) => { if (e.target.type === 'radio' && e.target.name === 'target-ip-option') { updateNoteArea(e.target.value); if (appState.currentView === 'search') handleSearch(); else showBookmarks(); } }); targetSelectorContainer.addEventListener('click', (e) => { const deleteBtn = e.target.closest('.delete-ip-btn'); if (deleteBtn) { e.preventDefault(); const ipToDelete = deleteBtn.dataset.ip; if (ipToDelete) { const currentIPs = targetListInput.value.split('\n').map(i => i.trim()).filter(Boolean); const newIPs = currentIPs.filter(ip => ip !== ipToDelete); targetListInput.value = newIPs.join('\n'); generateTargetSelectors(); } } }); playbookSearchInput.addEventListener('input', (e) => { renderPlaybookSuggestions(e.target.value); }); playbookSearchInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && playbookSearchInput.value.trim() !== '') { e.preventDefault(); const firstSuggestion = playbookSuggestionBox.querySelector('.suggestion-item'); if (firstSuggestion && playbookSuggestionBox.style.display === 'block') { const keyword = firstSuggestion.dataset.keyword; addPlaybookTag(keyword); } } }); document.addEventListener('click', (e) => { if (!playbookSearchInput.contains(e.target) && !playbookSuggestionBox.contains(e.target)) { playbookSuggestionBox.style.display = 'none'; } }); playbookSuggestionBox.addEventListener('click', (e) => { const item = e.target.closest('.suggestion-item'); if (item) { const keyword = item.dataset.keyword; addPlaybookTag(keyword); } }); playbookSelectedTags.addEventListener('click', (e) => { const removeBtn = e.target.closest('.remove-tag-btn'); if (removeBtn) { const keyword = removeBtn.dataset.keyword; removePlaybookTag(keyword); } }); if (clearMainSearchBtn && searchInput) {
        clearMainSearchBtn.addEventListener('click', () => {
            searchInput.value = '';
            handleSearch(); // Cập nhật kết quả
            searchInput.focus(); // Focus lại input
        });
        // Hiện/ẩn nút clear khi gõ vào main search
        searchInput.addEventListener('input', handleSearch); // handleSearch đã chứa logic này
    };

    if (clearPlaybookSearchBtn && playbookSearchInput) {
        clearPlaybookSearchBtn.addEventListener('click', () => {
            playbookSearchInput.value = '';
            renderPlaybookSuggestions(''); // Ẩn gợi ý
            clearPlaybookSearchBtn.style.display = 'none'; // Ẩn nút clear
            playbookSearchInput.focus(); // Focus lại input
        });
        // Hiện/ẩn nút clear khi gõ vào playbook search
        playbookSearchInput.addEventListener('input', (e) => {
            const query = e.target.value;
            renderPlaybookSuggestions(query); // Gọi hàm gợi ý (đã có)
            clearPlaybookSearchBtn.style.display = query ? 'flex' : 'none'; // Hiện/ẩn nút
        });
    }

    // *** THÊM: Listener cho nút Copy Kali IP ***
    if (copyKaliIpBtn && myKaliIpDisplay) {
        copyKaliIpBtn.addEventListener('click', () => {
            const ipFoundText = translations[appState.currentLang]?.ipFound || 'Local IP:';
            let ipToCopy = '';
            if (kaliIpInput.value.startsWith(ipFoundText)) {
                ipToCopy = kaliIpInput.value.substring(ipFoundText.length).trim();
            } else if (kaliIpInput.value.startsWith('Found: ')) {
                // Lấy IP từ thông báo "Found: ..."
                ipToCopy = kaliIpInput.value.split(' ')[1];
            }

            if (ipToCopy) {
                navigator.clipboard.writeText(ipToCopy).then(() => {
                    copyKaliIpBtn.classList.add('copied'); // Thêm class để đổi màu icon (CSS xử lý)
                    // Giữ tooltip gốc nếu có
                    const originalTitle = copyKaliIpBtn.title;
                    copyKaliIpBtn.title = translations[appState.currentLang]?.copied || 'Copied!';
                    setTimeout(() => {
                        copyKaliIpBtn.classList.remove('copied');
                        copyKaliIpBtn.title = originalTitle; // Khôi phục tooltip gốc
                    }, 1500);
                }).catch(err => {
                    console.error('Failed to copy IP: ', err);
                    alert('Failed to copy IP!');
                });
            }
        });
    }
};
  const addPlaybookTag = (keyword) => { if (keyword && !appState.playbookSearchTags.includes(keyword)) { appState.playbookSearchTags.push(keyword); savePlaybookTags(); renderSelectedPlaybookTags(); findRecommendedPlaybook(); } playbookSearchInput.value = ''; playbookSuggestionBox.innerHTML = ''; playbookSuggestionBox.style.display = 'none'; playbookSearchInput.focus(); };
  const removePlaybookTag = (keyword) => { if (keyword) { appState.playbookSearchTags = appState.playbookSearchTags.filter(tag => tag !== keyword); savePlaybookTags(); renderSelectedPlaybookTags(); findRecommendedPlaybook(); } };
  const savePlaybookTags = () => { try { localStorage.setItem(`sch_${appState.activeProject}_playbook_tags`, JSON.stringify(appState.playbookSearchTags)); } catch (error) { console.error("Failed to save playbook tags to localStorage:", error); alert("Error saving playbook tags."); } };


  // ========== 7. APP INITIALIZATION ==========
  const initializeApp = () => {
    // Tạo map knowledgeData
    if (typeof KNOWLEDGEDATA !== 'undefined' && Array.isArray(KNOWLEDGEDATA)) { // Thêm kiểm tra
        KNOWLEDGEDATA.forEach(item => {
            if(item && item.id) { // Kiểm tra item và id
               knowledgeDataMap[item.id] = item;
            }
        });
        // Khởi tạo Fuse
        fuse = new Fuse(KNOWLEDGEDATA, fuseOptions);
    } else {
        console.error("knowledgeData is not defined or not an array!");
        // Có thể hiển thị lỗi cho người dùng hoặc dừng ứng dụng
        resultsContainer.innerHTML = "<p style='color: red; text-align: center;'>Error loading knowledge data!</p>";
        return; // Dừng khởi tạo nếu dữ liệu lỗi
    }


    // Tạo dữ liệu playbook
    if (typeof PLAYBOOKS !== 'undefined' && typeof TECHNOLOGIES !== 'undefined') { // Thêm kiểm tra
       createPlaybookData();
    } else {
       console.error("PLAYBOOKS or TECHNOLOGIES data is missing!");
       // Ẩn hoặc thông báo lỗi cho phần playbook
       const rightSidebarWidget = document.querySelector('.right-sidebar .sidebar-widget');
       if(rightSidebarWidget) rightSidebarWidget.innerHTML = "<p style='color: red;'>Error loading playbook data!</p>";
    }


    // Khởi tạo các thành phần khác (chỉ khi dữ liệu cơ bản ổn)
    if (noteContentTextarea) { // Chỉ khởi tạo note nếu textarea tồn tại
       initializeNoteEditor();
    } else {
       console.error("Note textarea not found, skipping note initialization.");
    }

    applyTheme(appState.currentTheme);
    populateProjectSelector();
    initEventListeners(); // Gắn listener sau khi các element chắc chắn tồn tại
    loadProjectData(); // Load dữ liệu project (phụ thuộc vào các hàm khác đã khởi tạo)
    setLanguage(appState.currentLang); // Đặt ngôn ngữ cuối cùng để cập nhật tất cả text

    // handleGetKaliIP(); // Tùy chọn: Tự động lấy IP khi load
    // handleGetKaliIP(); // Gọi lần đầu ngay khi tải trang
    // setInterval(handleGetKaliIP, 10000); // Lặp lại mỗi 5 giây


  };

  initializeApp(); // Bắt đầu ứng dụng
});
