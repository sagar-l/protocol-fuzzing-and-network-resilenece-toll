// ============================================================================
// FuzzStrike Dashboard — Application Logic
// ============================================================================
// Handles all client-side functionality for the Glassmorphism dashboard:
//
//   1. C2 API Communication (polling metrics, creating campaigns)
//   2. Real-time Canvas Chart (attack throughput visualization)
//   3. Crash Triage Table (dynamic row rendering with animations)
//   4. Toast Notification System
//   5. Campaign Control (create, start, stop)
//
// Architecture:
//   - Pure vanilla JS (no frameworks, no dependencies)
//   - ES6+ features (classes, async/await, template literals)
//   - Canvas 2D API for chart rendering (no chart library)
//   - Polling-based updates (every 3 seconds)
//
// The dashboard proxies all API calls through Nginx (/api/*) to
// avoid CORS issues. When running locally without Docker, update
// the API_BASE constant below.
// ============================================================================

'use strict';

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
    // API base URL — proxied through Nginx in Docker.
    // For local development, change to: 'http://localhost:9000'
    API_BASE: '/api/v1',

    // Polling interval for metrics updates (milliseconds)
    POLL_INTERVAL_MS: 3000,

    // Chart configuration
    CHART_MAX_POINTS: 60,        // Number of data points visible on chart
    CHART_ANIMATION_MS: 16,      // ~60fps animation frame time

    // Toast duration (milliseconds)
    TOAST_DURATION_MS: 4000,
};


// ============================================================================
// Toast Notification System
// ============================================================================

/**
 * Lightweight toast notification system.
 * 
 * Supports 4 types: success, error, warning, info
 * Toasts auto-dismiss after CONFIG.TOAST_DURATION_MS.
 * Multiple toasts stack vertically in the bottom-right corner.
 */
const Toast = {
    container: null,

    init() {
        this.container = document.getElementById('toast-container');
    },

    /**
     * Show a toast notification.
     * @param {string} message - The message to display.
     * @param {'success'|'error'|'warning'|'info'} type - Toast type.
     */
    show(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast--${type}`;
        toast.textContent = message;

        this.container.appendChild(toast);

        // Auto-dismiss with exit animation
        setTimeout(() => {
            toast.classList.add('toast--exit');
            setTimeout(() => toast.remove(), 300);
        }, CONFIG.TOAST_DURATION_MS);
    },

    success(msg) { this.show(msg, 'success'); },
    error(msg)   { this.show(msg, 'error'); },
    warning(msg) { this.show(msg, 'warning'); },
    info(msg)    { this.show(msg, 'info'); },
};


// ============================================================================
// API Client
// ============================================================================

/**
 * REST client for the C2 orchestrator API.
 * All methods return parsed JSON or throw on error.
 */
const API = {
    /**
     * Generic fetch wrapper with error handling.
     * @param {string} endpoint - API endpoint (relative to API_BASE).
     * @param {object} options - Fetch options override.
     * @returns {Promise<any>} Parsed JSON response.
     */
    async request(endpoint, options = {}) {
        const url = `${CONFIG.API_BASE}${endpoint}`;

        const defaults = {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
        };

        const response = await fetch(url, { ...defaults, ...options });

        if (!response.ok) {
            const errorBody = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorBody}`);
        }

        return response.json();
    },

    // ── Health ────────────────────────────────────────────────────────
    async healthCheck() {
        const resp = await fetch('/health');
        return resp.ok;
    },

    // ── Campaigns ────────────────────────────────────────────────────
    async createCampaign(data) {
        return this.request('/campaigns/', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },

    async startCampaign(id) {
        return this.request(`/campaigns/${id}/start`, { method: 'POST' });
    },

    async stopCampaign(id) {
        return this.request(`/campaigns/${id}/stop`, { method: 'POST' });
    },

    async listCampaigns(status = null) {
        const query = status ? `?status=${status}` : '';
        return this.request(`/campaigns/${query}`);
    },

    // ── Metrics ──────────────────────────────────────────────────────
    async getDashboardMetrics() {
        return this.request('/campaigns/metrics/dashboard');
    },

    // ── Telemetry ────────────────────────────────────────────────────
    async listCrashes(limit = 20) {
        return this.request(`/telemetry/crashes?limit=${limit}`);
    },
};


// ============================================================================
// Real-Time Chart (Canvas 2D)
// ============================================================================

/**
 * Custom canvas-based line chart for visualizing attack throughput.
 * 
 * Features:
 *   - Dual-line chart (payloads sent + crashes)
 *   - Smooth gradient fills under lines
 *   - Animated data point transitions
 *   - Grid lines with labels
 *   - Responsive to container resizing
 *   - Hardware-accelerated rendering
 */
class AttackChart {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');

        // Data stores — circular buffers of metric snapshots
        this.sentData = [];
        this.crashData = [];
        this.labels = [];
        this.maxPoints = CONFIG.CHART_MAX_POINTS;

        // Track previous values to compute deltas
        this.prevSent = 0;
        this.prevCrash = 0;

        // Colors
        this.sentColor = '#6366f1';
        this.crashColor = '#ef4444';
        this.gridColor = 'rgba(99, 102, 241, 0.08)';
        this.labelColor = 'rgba(148, 163, 184, 0.6)';

        // Handle resize
        this.resizeObserver = new ResizeObserver(() => this.resize());
        this.resizeObserver.observe(this.canvas.parentElement);
        this.resize();

        // Initial empty render
        this.render();
    }

    /**
     * Handle canvas resize to maintain crisp rendering.
     * Uses devicePixelRatio for high-DPI display support.
     */
    resize() {
        const container = this.canvas.parentElement;
        const dpr = window.devicePixelRatio || 1;
        const rect = container.getBoundingClientRect();

        this.canvas.width = rect.width * dpr;
        this.canvas.height = rect.height * dpr;
        this.ctx.scale(dpr, dpr);

        this.width = rect.width;
        this.height = rect.height;

        this.render();
    }

    /**
     * Push a new data point from the metrics poll.
     * @param {number} totalSent - Cumulative payloads sent.
     * @param {number} totalCrash - Cumulative crashes.
     */
    pushData(totalSent, totalCrash) {
        // Compute delta (payloads sent since last poll)
        const deltaSent = Math.max(0, totalSent - this.prevSent);
        const deltaCrash = Math.max(0, totalCrash - this.prevCrash);

        this.prevSent = totalSent;
        this.prevCrash = totalCrash;

        this.sentData.push(deltaSent);
        this.crashData.push(deltaCrash);

        const now = new Date();
        this.labels.push(now.toLocaleTimeString('en-US', { 
            hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' 
        }));

        // Trim to max points (circular buffer behavior)
        if (this.sentData.length > this.maxPoints) {
            this.sentData.shift();
            this.crashData.shift();
            this.labels.shift();
        }

        this.render();
    }

    /**
     * Render the chart on the canvas.
     * Called on every data update and resize event.
     */
    render() {
        const ctx = this.ctx;
        const w = this.width;
        const h = this.height;

        if (!w || !h) return;

        // Clear canvas
        ctx.clearRect(0, 0, w, h);

        // Chart area with padding
        const padding = { top: 20, right: 20, bottom: 35, left: 50 };
        const chartW = w - padding.left - padding.right;
        const chartH = h - padding.top - padding.bottom;

        // Compute Y-axis scale
        const allValues = [...this.sentData, ...this.crashData];
        const maxVal = Math.max(10, ...allValues);
        const niceMax = Math.ceil(maxVal / 5) * 5;

        // ── Draw grid lines ──────────────────────────────────────────
        const gridLines = 5;
        ctx.strokeStyle = this.gridColor;
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 4]);

        for (let i = 0; i <= gridLines; i++) {
            const y = padding.top + (chartH / gridLines) * i;
            ctx.beginPath();
            ctx.moveTo(padding.left, y);
            ctx.lineTo(w - padding.right, y);
            ctx.stroke();

            // Y-axis labels
            const value = Math.round(niceMax - (niceMax / gridLines) * i);
            ctx.fillStyle = this.labelColor;
            ctx.font = '10px "JetBrains Mono", monospace';
            ctx.textAlign = 'right';
            ctx.fillText(value, padding.left - 8, y + 4);
        }
        ctx.setLineDash([]);

        // ── Draw X-axis labels ───────────────────────────────────────
        if (this.labels.length > 0) {
            const labelStep = Math.max(1, Math.floor(this.labels.length / 6));
            ctx.fillStyle = this.labelColor;
            ctx.font = '9px "JetBrains Mono", monospace';
            ctx.textAlign = 'center';

            for (let i = 0; i < this.labels.length; i += labelStep) {
                const x = padding.left + (chartW / Math.max(1, this.sentData.length - 1)) * i;
                ctx.fillText(this.labels[i], x, h - 8);
            }
        }

        if (this.sentData.length < 2) {
            // Not enough data — draw placeholder text
            ctx.fillStyle = this.labelColor;
            ctx.font = '13px "Inter", sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('Waiting for data...', w / 2, h / 2);
            return;
        }

        // ── Helper: Map data points to canvas coordinates ────────────
        const mapPoints = (data) => {
            return data.map((val, i) => ({
                x: padding.left + (chartW / (data.length - 1)) * i,
                y: padding.top + chartH - (val / niceMax) * chartH,
            }));
        };

        // ── Draw filled area + line for "Sent" data ──────────────────
        const sentPoints = mapPoints(this.sentData);
        this.drawLine(ctx, sentPoints, this.sentColor, padding, chartH);

        // ── Draw filled area + line for "Crash" data ─────────────────
        const crashPoints = mapPoints(this.crashData);
        this.drawLine(ctx, crashPoints, this.crashColor, padding, chartH);

        // ── Draw data point dots ─────────────────────────────────────
        this.drawDots(ctx, sentPoints, this.sentColor);
        this.drawDots(ctx, crashPoints, this.crashColor);
    }

    /**
     * Draw a line with gradient fill underneath.
     */
    drawLine(ctx, points, color, padding, chartH) {
        if (points.length < 2) return;

        // Gradient fill
        const gradient = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartH);
        gradient.addColorStop(0, color + '30');   // 19% opacity at top
        gradient.addColorStop(1, color + '00');   // 0% opacity at bottom

        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);
        for (let i = 1; i < points.length; i++) {
            // Smooth curve using quadratic bezier
            const xc = (points[i].x + points[i - 1].x) / 2;
            const yc = (points[i].y + points[i - 1].y) / 2;
            ctx.quadraticCurveTo(points[i - 1].x, points[i - 1].y, xc, yc);
        }
        ctx.quadraticCurveTo(
            points[points.length - 1].x, points[points.length - 1].y,
            points[points.length - 1].x, points[points.length - 1].y
        );

        // Fill area under the curve
        const lastPoint = points[points.length - 1];
        const firstPoint = points[0];
        ctx.lineTo(lastPoint.x, padding.top + chartH);
        ctx.lineTo(firstPoint.x, padding.top + chartH);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        // Draw the line itself
        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);
        for (let i = 1; i < points.length; i++) {
            const xc = (points[i].x + points[i - 1].x) / 2;
            const yc = (points[i].y + points[i - 1].y) / 2;
            ctx.quadraticCurveTo(points[i - 1].x, points[i - 1].y, xc, yc);
        }
        ctx.quadraticCurveTo(
            points[points.length - 1].x, points[points.length - 1].y,
            points[points.length - 1].x, points[points.length - 1].y
        );
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();
    }

    /**
     * Draw small dots at each data point.
     */
    drawDots(ctx, points, color) {
        // Only draw dots on the last 5 points to avoid clutter
        const startIdx = Math.max(0, points.length - 5);
        for (let i = startIdx; i < points.length; i++) {
            const pt = points[i];
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 3, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
            ctx.strokeStyle = '#060918';
            ctx.lineWidth = 1.5;
            ctx.stroke();
        }
    }
}


// ============================================================================
// Dashboard Application Controller
// ============================================================================

/**
 * Main application controller that orchestrates all dashboard functionality.
 * Manages state, polling, and UI updates.
 */
class DashboardApp {
    constructor() {
        // State
        this.activeCampaignId = null;
        this.isPolling = false;
        this.pollTimer = null;
        this.startTime = Date.now();
        this.knownCrashIds = new Set();

        // Chart instance
        this.chart = null;

        // DOM references (cached for performance)
        this.dom = {};
    }

    /**
     * Initialize the dashboard application.
     * Called once when the page loads.
     */
    init() {
        // Initialize subsystems
        Toast.init();
        this.cacheDomRefs();
        this.chart = new AttackChart('attack-chart');
        this.bindEvents();

        // Start the connection check and polling
        this.checkC2Connection();
        this.startPolling();
        this.startUptimeCounter();

        // Update footer time 
        this.updateFooterTime();
        setInterval(() => this.updateFooterTime(), 1000);

        console.log('%c⚡ FuzzStrike Dashboard Initialized', 
            'color: #6366f1; font-size: 14px; font-weight: bold;');
    }

    /**
     * Cache frequently accessed DOM elements.
     */
    cacheDomRefs() {
        this.dom = {
            // Status
            statusDot: document.getElementById('status-dot'),
            statusText: document.getElementById('status-text'),

            // Metrics
            totalCampaigns: document.getElementById('metric-total-campaigns'),
            activeCampaigns: document.getElementById('metric-active-campaigns'),
            payloadsSent: document.getElementById('metric-payloads-sent'),
            payloadsGenerated: document.getElementById('metric-payloads-generated'),
            crashesDetected: document.getElementById('metric-crashes-detected'),
            crashRate: document.getElementById('metric-crash-rate'),
            throughput: document.getElementById('metric-throughput'),
            uptime: document.getElementById('metric-uptime'),

            // Campaign form 
            form: document.getElementById('campaign-form'),
            campaignName: document.getElementById('campaign-name'),
            seedPayload: document.getElementById('seed-payload'),
            targetHost: document.getElementById('target-host'),
            targetPort: document.getElementById('target-port'),
            mutationCount: document.getElementById('mutation-count'),
            mutationCountDisplay: document.getElementById('mutation-count-display'),
            btnCreate: document.getElementById('btn-create-campaign'),
            btnStop: document.getElementById('btn-stop-campaign'),

            // Active campaign
            activeCampaignEl: document.getElementById('active-campaign'),
            activeCampaignName: document.getElementById('active-campaign-name'),
            campaignProgress: document.getElementById('campaign-progress'),
            campaignProgressLabel: document.getElementById('campaign-progress-label'),

            // Triage
            triageTbody: document.getElementById('triage-tbody'),
            triageEmpty: document.getElementById('triage-empty'),
            crashCountBadge: document.getElementById('crash-count-badge'),

            // Footer
            footerTime: document.getElementById('footer-time'),
        };
    }

    /**
     * Bind event handlers.
     */
    bindEvents() {
        // Campaign form submission
        this.dom.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.createAndStartCampaign();
        });

        // Stop button
        this.dom.btnStop.addEventListener('click', () => {
            this.stopCampaign();
        });

        // Mutation count slider
        this.dom.mutationCount.addEventListener('input', (e) => {
            this.dom.mutationCountDisplay.textContent = e.target.value;
        });
    }

    // ── C2 Connection ─────────────────────────────────────────────────

    async checkC2Connection() {
        try {
            const healthy = await API.healthCheck();
            if (healthy) {
                this.dom.statusDot.className = 'status-dot status-dot--online';
                this.dom.statusText.textContent = 'C2 Online';
            } else {
                throw new Error('Unhealthy');
            }
        } catch {
            this.dom.statusDot.className = 'status-dot status-dot--offline';
            this.dom.statusText.textContent = 'C2 Offline';
        }
    }

    // ── Polling Loop ──────────────────────────────────────────────────

    startPolling() {
        if (this.isPolling) return;
        this.isPolling = true;

        const poll = async () => {
            try {
                await this.fetchAndUpdateMetrics();
                await this.fetchAndUpdateCrashes();
                await this.checkC2Connection();
            } catch (err) {
                console.warn('Poll error:', err.message);
            }

            if (this.isPolling) {
                this.pollTimer = setTimeout(poll, CONFIG.POLL_INTERVAL_MS);
            }
        };

        poll(); // Initial poll 
    }

    stopPolling() {
        this.isPolling = false;
        if (this.pollTimer) {
            clearTimeout(this.pollTimer);
            this.pollTimer = null;
        }
    }

    // ── Metrics Update ────────────────────────────────────────────────

    async fetchAndUpdateMetrics() {
        try {
            const metrics = await API.getDashboardMetrics();

            // Update metric cards with animated number transitions
            this.animateValue(this.dom.totalCampaigns, metrics.total_campaigns);
            this.dom.activeCampaigns.textContent = `${metrics.active_campaigns} active`;

            this.animateValue(this.dom.payloadsSent, metrics.total_payloads_sent);
            this.dom.payloadsGenerated.textContent = `${metrics.total_payloads_generated.toLocaleString()} generated`;

            this.animateValue(this.dom.crashesDetected, metrics.total_crashes_detected);
            this.dom.crashRate.textContent = `${metrics.crash_rate_percent}% crash rate`;

            // Compute throughput (payloads per second since start)
            const elapsedSec = (Date.now() - this.startTime) / 1000;
            const throughput = elapsedSec > 0 
                ? (metrics.total_payloads_sent / elapsedSec).toFixed(1) 
                : '0';
            this.dom.throughput.textContent = throughput;

            // Push data to chart
            this.chart.pushData(
                metrics.total_payloads_sent,
                metrics.total_crashes_detected
            );

            // Update active campaign progress if one exists
            if (metrics.active_campaigns > 0) {
                await this.updateActiveCampaignProgress();
            }

        } catch (err) {
            // Silently handle — don't spam errors to the user
            console.debug('Metrics fetch failed:', err.message);
        }
    }

    /**
     * Animate a metric value from its current display to a new value.
     * Creates a smooth counting-up effect.
     */
    animateValue(element, newValue) {
        const current = parseInt(element.textContent.replace(/,/g, '')) || 0;
        if (current === newValue) return;

        const duration = 500;
        const startTime = performance.now();

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            // Ease-out cubic
            const eased = 1 - Math.pow(1 - progress, 3);
            const value = Math.round(current + (newValue - current) * eased);

            element.textContent = value.toLocaleString();

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    }

    // ── Active Campaign Progress ──────────────────────────────────────

    async updateActiveCampaignProgress() {
        try {
            const campaigns = await API.listCampaigns('running');
            if (campaigns.length > 0) {
                const campaign = campaigns[0];
                this.activeCampaignId = campaign.id;

                this.dom.activeCampaignEl.style.display = 'block';
                this.dom.activeCampaignName.textContent = campaign.name;
                this.dom.btnStop.disabled = false;

                const progress = campaign.total_payloads > 0
                    ? (campaign.payloads_sent / campaign.total_payloads) * 100
                    : 0;

                this.dom.campaignProgress.style.width = `${Math.min(100, progress)}%`;
                this.dom.campaignProgressLabel.textContent = 
                    `${campaign.payloads_sent}/${campaign.total_payloads} payloads`;
            } else {
                this.dom.activeCampaignEl.style.display = 'none';
                this.dom.btnStop.disabled = true;
                this.activeCampaignId = null;
            }
        } catch {
            // Ignore
        }
    }

    // ── Crash Triage ──────────────────────────────────────────────────

    async fetchAndUpdateCrashes() {
        try {
            const crashes = await API.listCrashes(20);

            if (crashes.length === 0) return;

            // Update badge count
            this.dom.crashCountBadge.textContent = `${crashes.length} crashes`;

            // Hide empty state
            this.dom.triageEmpty.style.display = 'none';

            // Check for new crashes (for toast notifications)
            for (const crash of crashes) {
                if (!this.knownCrashIds.has(crash.id)) {
                    this.knownCrashIds.add(crash.id);
                    if (this.knownCrashIds.size > 1) { // Skip initial load
                        Toast.warning(
                            `🔥 New crash detected: ${crash.error_type || 'Unknown'} ` +
                            `(${this.formatBytes(crash.trigger_payload_size)})`
                        );
                    }
                }
            }

            // Rebuild the table
            this.renderCrashTable(crashes);

        } catch (err) {
            console.debug('Crash fetch failed:', err.message);
        }
    }

    /**
     * Render crash reports into the triage table.
     */
    renderCrashTable(crashes) {
        // Keep empty state row, clear everything else
        const rows = this.dom.triageTbody.querySelectorAll('tr:not(.triage-empty)');
        rows.forEach(r => r.remove());

        for (const crash of crashes) {
            const row = document.createElement('tr');
            row.className = this.knownCrashIds.size <= crashes.length ? '' : 'crash-new';

            const severityClass = `badge--${crash.severity || 'medium'}`;
            const timestamp = new Date(crash.timestamp).toLocaleString('en-US', {
                hour12: false,
                month: 'short', day: '2-digit',
                hour: '2-digit', minute: '2-digit', second: '2-digit',
            });

            row.innerHTML = `
                <td class="mono">#${crash.id}</td>
                <td class="mono">${timestamp}</td>
                <td><span class="badge ${severityClass}">${(crash.severity || 'medium').toUpperCase()}</span></td>
                <td>${this.escapeHtml(crash.error_type || 'Unknown')}</td>
                <td class="mono">${this.formatBytes(crash.trigger_payload_size)}</td>
                <td class="mono">${crash.memory_rss_mb ? crash.memory_rss_mb.toFixed(1) + ' MB' : '—'}</td>
                <td><span class="payload-preview" title="${this.escapeHtml(crash.error_message || '')}">${this.escapeHtml((crash.error_message || '—').substring(0, 60))}</span></td>
            `;

            this.dom.triageTbody.insertBefore(row, this.dom.triageEmpty);
        }
    }

    // ── Campaign Control ──────────────────────────────────────────────

    async createAndStartCampaign() {
        const name = this.dom.campaignName.value.trim();
        const seedPayload = this.dom.seedPayload.value.trim();
        const targetHost = this.dom.targetHost.value.trim() || 'target';
        const targetPort = parseInt(this.dom.targetPort.value) || 7777;
        const mutationCount = parseInt(this.dom.mutationCount.value) || 50;

        // Validate seed is valid JSON
        try {
            JSON.parse(seedPayload);
        } catch {
            Toast.error('Invalid JSON in seed payload. Please check the syntax.');
            this.dom.seedPayload.focus();
            return;
        }

        if (!name) {
            Toast.error('Please provide a campaign name.');
            this.dom.campaignName.focus();
            return;
        }

        // Disable button during creation
        this.dom.btnCreate.disabled = true;
        this.dom.btnCreate.textContent = 'Creating...';

        try {
            // Step 1: Create campaign (generates mutations)
            Toast.info(`Creating campaign "${name}" with ${mutationCount} mutations...`);

            const campaign = await API.createCampaign({
                name,
                seed_payload: seedPayload,
                target_host: targetHost,
                target_port: targetPort,
                mutation_count: mutationCount,
            });

            Toast.success(`Campaign "${name}" created with ${campaign.total_payloads} payloads!`);

            // Step 2: Start the campaign
            await API.startCampaign(campaign.id);
            this.activeCampaignId = campaign.id;

            Toast.success(`Campaign "${name}" started! Attack in progress...`);

            // Update UI
            this.dom.activeCampaignEl.style.display = 'block';
            this.dom.activeCampaignName.textContent = name;
            this.dom.btnStop.disabled = false;
            this.dom.campaignProgress.style.width = '0%';
            this.dom.campaignProgressLabel.textContent = `0/${campaign.total_payloads} payloads`;

            // Reset start time for throughput calculation
            this.startTime = Date.now();

        } catch (err) {
            Toast.error(`Failed to create campaign: ${err.message}`);
            console.error('Campaign creation error:', err);
        } finally {
            this.dom.btnCreate.disabled = false;
            this.dom.btnCreate.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                Create & Start
            `;
        }
    }

    async stopCampaign() {
        if (!this.activeCampaignId) {
            Toast.warning('No active campaign to stop.');
            return;
        }

        try {
            await API.stopCampaign(this.activeCampaignId);
            Toast.info('Campaign stopped.');

            this.dom.activeCampaignEl.style.display = 'none';
            this.dom.btnStop.disabled = true;
            this.activeCampaignId = null;

        } catch (err) {
            Toast.error(`Failed to stop campaign: ${err.message}`);
        }
    }

    // ── Uptime Counter ────────────────────────────────────────────────

    startUptimeCounter() {
        setInterval(() => {
            const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
            const hours = Math.floor(elapsed / 3600);
            const mins = Math.floor((elapsed % 3600) / 60);
            const secs = elapsed % 60;

            if (hours > 0) {
                this.dom.uptime.textContent = `${hours}h ${mins}m uptime`;
            } else if (mins > 0) {
                this.dom.uptime.textContent = `${mins}m ${secs}s uptime`;
            } else {
                this.dom.uptime.textContent = `${secs}s uptime`;
            }
        }, 1000);
    }

    // ── Footer ────────────────────────────────────────────────────────

    updateFooterTime() {
        this.dom.footerTime.textContent = new Date().toLocaleString('en-US', {
            hour12: false,
            year: 'numeric', month: 'short', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        });
    }

    // ── Utilities ─────────────────────────────────────────────────────

    /**
     * Format bytes to a human-readable string.
     */
    formatBytes(bytes) {
        if (bytes == null || bytes === 0) return '—';
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    /**
     * Escape HTML to prevent XSS in dynamic content.
     */
    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
}


// ============================================================================
// Bootstrap
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    const app = new DashboardApp();
    app.init();
});
