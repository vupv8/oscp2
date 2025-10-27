// ========== PHẦN 1: DỮ LIỆU TỪ KHUNG GỐC (CẬP NHẬT) ==========
const translations = {
  vi: {
    projectTitle: "Quản lý Project", newProjectBtn: "Tạo Project Mới", promptNewProject: "Nhập tên project mới:", defaultProject: "Project Mặc định",
    searchInputPlaceholder: "Tìm kiếm nmap, reverse shell, privesc...",
    searchBtn: "Tìm kiếm", bookmarkBtn: "Yêu thích",
    targetListTitle: "Danh sách IP mục tiêu", myKaliIpTitle: "My Kali IP", targetListPlaceholder: "Dán IP vào đây...",
    initialMessage: "Nhập từ khóa để tìm kiếm trong cơ sở tri thức.",
    noResults: "Không tìm thấy kết quả.",
    noBookmarks: "Bạn chưa lưu bookmark nào.", // Đã có sẵn, tốt!
    searchHint: "Nhập ít nhất 2 ký tự.", copy: "Copy", copied: "Đã chép!",
    bookmarkAction: "Lưu", exportAction: "Xuất Markdown", gettingIP: "Đang tìm IP...",
    ipFound: "IP nội bộ:", ipNotFound: "Không tìm thấy IP. Vui lòng truy cập chrome://flags và DISABLING the flag Anonymize local IPs exposed by WebRTC",
    notesFor: "Ghi chú cho", notePlaceholder: "Ghi lại các thông tin tìm được ở đây...", downloadLogTitle: "Tải về file log",
    matchedIn: "Khớp trong:", playbookTitle: "OSCP Playbook", playbookRecommend: "Kịch bản đề xuất", playbookInitial: "Chọn công nghệ để xem kịch bản.",
    playbookSearchPlaceholder: "Tìm LFI, Linux, Privesc...", // Thêm dòng này
        playbookInitial: "Chọn từ khóa để tìm playbook.",
        toggleThemeTitle: "Chuyển đổi giao diện Sáng/Tối",
        refreshKaliIpTitle: "Làm mới IP Kali",
        savingStatus: "Đang lưu...",
    savedStatus: "Đã lưu",
    errorStatus: "Lỗi lưu!",
    copyKaliIpTitle: "Sao chép IP Kali",
    assumptionLabel: "Giả định:",
  },
  en: {
    projectTitle: "Project Management", newProjectBtn: "New Project", promptNewProject: "Enter new project name:", defaultProject: "Default Project",
    searchInputPlaceholder: "Search nmap, reverse shell, privesc...",
    searchBtn: "Search", bookmarkBtn: "Bookmarks",
    targetListTitle: "Target IP List", myKaliIpTitle: "My Kali IP", targetListPlaceholder: "Paste IPs here...",
    initialMessage: "Enter a keyword to search the knowledge base.",
    noResults: "No results found.",
    noBookmarks: "You don't have any bookmarks yet.", // Đã có sẵn, tốt!
    searchHint: "Enter at least 2 characters.", copy: "Copy", copied: "Copied!",
    bookmarkAction: "Bookmark", exportAction: "Export Markdown", gettingIP: "Getting IP...",
    ipFound: "Local IP:", ipNotFound: "Local IP not found.Please go to chrome://flags and DISABLING the flag Anonymize local IPs exposed by WebRTC",
    notesFor: "Notes for", notePlaceholder: "Log your findings here...", downloadLogTitle: "Download log file",
    matchedIn: "Matched in:", playbookTitle: "OSCP Playbook", playbookRecommend: "Recommended Playbook", playbookInitial: "Select technologies to see a playbook.",
    playbookSearchPlaceholder: "Search LFI, Linux, Privesc...", // Add this line
        playbookInitial: "Select keywords to find playbooks.",
        toggleThemeTitle: "Toggle Light/Dark Theme",
        refreshKaliIpTitle: "Refresh Kali IP",
        savingStatus: "Saving...",
    savedStatus: "Saved",
    errorStatus: "Error saving!",
    copyKaliIpTitle: "Copy Kali IP",
    assumptionLabel: "Assumption:",
  }
};

