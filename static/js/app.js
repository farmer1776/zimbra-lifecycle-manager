/* Zimbra Lifecycle Manager - Frontend Application */

function app() {
    return {
        tab: 'dashboard',
        loading: false,
        syncing: false,
        syncStatusText: '',

        // Auth
        authenticated: false,
        currentUser: {},

        // Dashboard
        stats: {},
        domains: [],

        // Accounts
        accountData: { accounts: [], total: 0, page: 1, pages: 0, per_page: 50 },
        filters: { domain: '', status: '', search: '' },
        sortBy: 'email',
        sortDir: 'asc',

        // Purge
        purgeAccounts: [],

        // Audit
        auditData: { logs: [], total: 0, page: 1, pages: 0 },
        auditSearch: '',
        auditPage: 1,

        // CSV Bulk
        bulkMode: 'simple',
        csvFile: null,
        csvUploading: false,
        csvResults: null,
        bulkFile: null,
        bulkTargetStatus: '',
        bulkProcessing: false,

        // Users
        usersList: [],
        showAddUser: false,
        newUser: { username: '', password: '', display_name: '', role: 'operator' },

        // Modals
        modal: { show: false, title: '', message: '', btnText: '', btnClass: '', loading: false, input: false, inputLabel: '', inputType: 'text', inputValue: '', action: () => {} },
        detailModal: { show: false, account: null },

        // Toast
        toasts: [],

        async init() {
            // Check auth - redirect to login if no token
            const token = localStorage.getItem('token');
            if (!token) {
                window.location.replace('/login');
                return;
            }
            // Validate token with server
            try {
                this.currentUser = await this.api('/api/auth/me');
                if (!this.currentUser || !this.currentUser.id) {
                    throw new Error('Invalid session');
                }
            } catch (e) {
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                window.location.replace('/login');
                return;
            }
            this.authenticated = true;
            await this.loadDashboard();
            await this.loadDomains();
        },

        logout() {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.replace('/login');
        },

        // ── API Helper ──────────────────────────────────────

        async api(url, options = {}) {
            const token = localStorage.getItem('token');
            const headers = { ...(options.headers || {}) };
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            // Only set Content-Type for non-FormData
            if (!(options.body instanceof FormData)) {
                headers['Content-Type'] = 'application/json';
            }
            try {
                const resp = await fetch(url, { ...options, headers });
                if (resp.status === 401) {
                    localStorage.removeItem('token');
                    localStorage.removeItem('user');
                    window.location.replace('/login');
                    // Throw to stop all downstream calls
                    throw new Error('Session expired');
                }
                const data = await resp.json();
                if (!resp.ok) {
                    throw new Error(data.detail || `HTTP ${resp.status}`);
                }
                return data;
            } catch (e) {
                if (e.message !== 'Session expired') {
                    this.toast(e.message, 'error');
                }
                throw e;
            }
        },

        // ── Dashboard ───────────────────────────────────────

        async loadDashboard() {
            try {
                this.stats = await this.api('/api/dashboard');
            } catch (e) { /* toast already shown */ }
        },

        async loadDomains() {
            try {
                this.domains = await this.api('/api/domains');
            } catch (e) { /* toast already shown */ }
        },

        // ── Accounts ────────────────────────────────────────

        async loadAccounts() {
            this.loading = true;
            try {
                const params = new URLSearchParams();
                if (this.filters.domain) params.set('domain', this.filters.domain);
                if (this.filters.status) params.set('status', this.filters.status);
                if (this.filters.search) params.set('search', this.filters.search);
                params.set('page', this.accountData.page);
                params.set('per_page', this.accountData.per_page);
                params.set('sort_by', this.sortBy);
                params.set('sort_dir', this.sortDir);
                this.accountData = await this.api(`/api/accounts?${params}`);
            } catch (e) { /* toast already shown */ }
            this.loading = false;
        },

        sortAccounts(field) {
            if (this.sortBy === field) {
                this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                this.sortBy = field;
                this.sortDir = 'asc';
            }
            this.loadAccounts();
        },

        sortIcon(field) {
            if (this.sortBy !== field) return '';
            return this.sortDir === 'asc' ? '\u25B2' : '\u25BC';
        },

        changePage(p) {
            if (p < 1 || p > this.accountData.pages) return;
            this.accountData.page = p;
            this.loadAccounts();
        },

        resetFilters() {
            this.filters = { domain: '', status: '', search: '' };
            this.sortBy = 'email';
            this.sortDir = 'asc';
            this.accountData.page = 1;
            this.loadAccounts();
        },

        async exportCSV() {
            const params = new URLSearchParams();
            if (this.filters.domain) params.set('domain', this.filters.domain);
            if (this.filters.status) params.set('status', this.filters.status);
            if (this.filters.search) params.set('search', this.filters.search);
            const token = localStorage.getItem('token');
            try {
                const resp = await fetch(`/api/accounts/export?${params}`, {
                    headers: { 'Authorization': `Bearer ${token}` },
                });
                if (!resp.ok) throw new Error('Export failed');
                const blob = await resp.blob();
                const disposition = resp.headers.get('Content-Disposition') || '';
                const match = disposition.match(/filename="(.+)"/);
                const filename = match ? match[1] : 'accounts_export.csv';
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                this.toast(`Exported ${this.accountData.total} accounts`, 'success');
            } catch (e) {
                this.toast(e.message, 'error');
            }
        },

        // ── Status Change ───────────────────────────────────

        confirmStatusChange(acct, newStatus) {
            const labels = { locked: 'Lock', closed: 'Close', active: 'Activate', maintenance: 'Maintenance' };
            this.modal = {
                show: true,
                title: `${labels[newStatus]} Account`,
                message: `Change <strong>${acct.email}</strong> status from <strong>${acct.account_status}</strong> to <strong>${newStatus}</strong>?`,
                btnText: labels[newStatus],
                btnClass: newStatus === 'closed' ? 'btn-danger' : newStatus === 'locked' ? 'btn-warning' : 'btn-primary',
                loading: false,
                input: false, inputLabel: '', inputType: 'text', inputValue: '',
                action: async () => {
                    this.modal.loading = true;
                    try {
                        await this.api(`/api/accounts/${acct.id}/status?new_status=${newStatus}`, { method: 'POST' });
                        this.toast(`${acct.email} changed to ${newStatus}`, 'success');
                        this.modal.show = false;
                        this.loadAccounts();
                        this.loadDashboard();
                    } catch (e) { /* toast already shown */ }
                    this.modal.loading = false;
                },
            };
        },

        showDetail(acct) {
            this.detailModal = { show: true, account: acct };
        },

        // ── Purge ───────────────────────────────────────────

        async loadPurgeEligible() {
            try {
                const data = await this.api('/api/accounts?purge_eligible=true&per_page=200');
                this.purgeAccounts = data.accounts || [];
            } catch (e) { /* toast already shown */ }
        },

        confirmPurge(acct) {
            if (acct.forwarding_addresses) {
                this.toast(`Cannot purge ${acct.email}: has forwarding address`, 'warning');
                return;
            }
            this.modal = {
                show: true,
                title: 'Purge Account',
                message: `<strong style="color:var(--red)">Permanently delete</strong> mailbox <strong>${acct.email}</strong>?<br><br>This action cannot be undone.`,
                btnText: 'Purge Account',
                btnClass: 'btn-danger',
                loading: false,
                input: false, inputLabel: '', inputType: 'text', inputValue: '',
                action: async () => {
                    this.modal.loading = true;
                    try {
                        await this.api(`/api/accounts/${acct.id}/purge`, { method: 'POST' });
                        this.toast(`${acct.email} purged successfully`, 'success');
                        this.modal.show = false;
                        this.loadPurgeEligible();
                        this.loadDashboard();
                    } catch (e) { /* toast already shown */ }
                    this.modal.loading = false;
                },
            };
        },

        // ── Bulk Operations ──────────────────────────────────

        async uploadBulkSimple() {
            if (!this.bulkFile || !this.bulkTargetStatus) return;
            this.bulkProcessing = true;
            this.csvResults = null;
            try {
                const formData = new FormData();
                formData.append('file', this.bulkFile);
                this.csvResults = await this.api(`/api/accounts/bulk-status?new_status=${this.bulkTargetStatus}`, {
                    method: 'POST',
                    body: formData,
                });
                const r = this.csvResults;
                this.toast(`Bulk change: ${r.success} success, ${r.errors} errors, ${r.skipped || 0} skipped out of ${r.total}`, r.errors ? 'warning' : 'success');
                this.loadDashboard();
            } catch (e) { /* toast already shown */ }
            this.bulkProcessing = false;
        },

        async uploadCSV() {
            if (!this.csvFile) return;
            this.csvUploading = true;
            this.csvResults = null;
            try {
                const formData = new FormData();
                formData.append('file', this.csvFile);
                this.csvResults = await this.api('/api/accounts/bulk-csv', {
                    method: 'POST',
                    body: formData,
                });
                const r = this.csvResults;
                this.toast(`CSV processed: ${r.success} success, ${r.errors} errors out of ${r.total} rows`, r.errors ? 'warning' : 'success');
                this.loadDashboard();
            } catch (e) { /* toast already shown */ }
            this.csvUploading = false;
        },

        // ── Sync ────────────────────────────────────────────

        async triggerSync() {
            this.syncing = true;
            this.syncStatusText = 'Syncing with Zimbra...';
            try {
                const result = await this.api('/api/sync', { method: 'POST' });
                const r = result.result || {};
                this.syncStatusText = `Synced: ${r.processed || 0} processed, ${r.added || 0} added, ${r.updated || 0} updated`;
                this.toast(`Sync complete: ${r.processed || 0} accounts processed`, 'success');
                this.loadDashboard();
                this.loadDomains();
                if (this.tab === 'accounts') this.loadAccounts();
                if (this.tab === 'purge') this.loadPurgeEligible();
            } catch (e) {
                this.syncStatusText = 'Sync failed';
            }
            this.syncing = false;
        },

        // ── Audit ───────────────────────────────────────────

        async loadAudit() {
            try {
                const params = new URLSearchParams();
                if (this.auditSearch) params.set('target', this.auditSearch);
                params.set('page', this.auditPage);
                this.auditData = await this.api(`/api/audit?${params}`);
            } catch (e) { /* toast already shown */ }
        },

        // ── User Management ─────────────────────────────────

        async loadUsers() {
            try {
                this.usersList = await this.api('/api/users');
            } catch (e) { /* toast already shown */ }
        },

        async addUser() {
            if (!this.newUser.username || !this.newUser.password) {
                this.toast('Username and password are required', 'error');
                return;
            }
            try {
                await this.api('/api/users', {
                    method: 'POST',
                    body: JSON.stringify(this.newUser),
                });
                this.toast(`User ${this.newUser.username} created`, 'success');
                this.newUser = { username: '', password: '', display_name: '', role: 'operator' };
                this.showAddUser = false;
                this.loadUsers();
            } catch (e) { /* toast already shown */ }
        },

        async toggleUserActive(u) {
            try {
                await this.api(`/api/users/${u.id}`, {
                    method: 'PUT',
                    body: JSON.stringify({ is_active: !u.is_active }),
                });
                this.toast(`${u.username} ${u.is_active ? 'disabled' : 'enabled'}`, 'success');
                this.loadUsers();
            } catch (e) { /* toast already shown */ }
        },

        async toggleUserRole(u) {
            const newRole = u.role === 'admin' ? 'operator' : 'admin';
            try {
                await this.api(`/api/users/${u.id}`, {
                    method: 'PUT',
                    body: JSON.stringify({ role: newRole }),
                });
                this.toast(`${u.username} role changed to ${newRole}`, 'success');
                this.loadUsers();
            } catch (e) { /* toast already shown */ }
        },

        promptChangePassword(u) {
            this.modal = {
                show: true,
                title: `Change Password: ${u.username}`,
                message: `Enter a new password for <strong>${u.username}</strong>.`,
                btnText: 'Change Password',
                btnClass: 'btn-primary',
                loading: false,
                input: true,
                inputLabel: 'New Password',
                inputType: 'password',
                inputValue: '',
                action: async () => {
                    if (!this.modal.inputValue) {
                        this.toast('Password cannot be empty', 'error');
                        return;
                    }
                    this.modal.loading = true;
                    try {
                        await this.api(`/api/users/${u.id}/password`, {
                            method: 'PUT',
                            body: JSON.stringify({ password: this.modal.inputValue }),
                        });
                        this.toast(`Password changed for ${u.username}`, 'success');
                        this.modal.show = false;
                    } catch (e) { /* toast already shown */ }
                    this.modal.loading = false;
                },
            };
        },

        confirmDeleteUser(u) {
            this.modal = {
                show: true,
                title: 'Delete User',
                message: `Permanently delete user <strong>${u.username}</strong>?`,
                btnText: 'Delete',
                btnClass: 'btn-danger',
                loading: false,
                input: false, inputLabel: '', inputType: 'text', inputValue: '',
                action: async () => {
                    this.modal.loading = true;
                    try {
                        await this.api(`/api/users/${u.id}`, { method: 'DELETE' });
                        this.toast(`User ${u.username} deleted`, 'success');
                        this.modal.show = false;
                        this.loadUsers();
                    } catch (e) { /* toast already shown */ }
                    this.modal.loading = false;
                },
            };
        },

        // ── Utilities ───────────────────────────────────────

        formatDate(d) {
            if (!d || d === 'None') return '-';
            try {
                const dt = new Date(d);
                if (isNaN(dt)) return d;
                return dt.toLocaleString('en-US', {
                    year: 'numeric', month: 'short', day: 'numeric',
                    hour: '2-digit', minute: '2-digit',
                });
            } catch { return d; }
        },

        truncate(str, len) {
            if (!str) return '';
            return str.length > len ? str.slice(0, len) + '...' : str;
        },

        toast(message, type = 'success') {
            this.toasts.push({ message, type });
            setTimeout(() => { this.toasts.shift(); }, 5000);
        },
    };
}
