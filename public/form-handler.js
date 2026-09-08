/**
 * FreeFormer Client Library
 * Easy integration for form submissions with Turnstile verification
 * 
 * Usage:
 * <script src="https://your-worker.workers.dev/form-handler.js"></script>
 * <script>
 *   FreeFormer.init({
 *     workerUrl: 'https://your-worker.workers.dev',
 *     turnstileSiteKey: 'YOUR_SITE_KEY'
 *   });
 * </script>
 */

(function (window) {
    'use strict';

    const FreeFormer = {
        config: {
            workerUrl: '',
            siteId: '',
            turnstileSiteKey: null,
            autoInit: true,
            debug: false
        },

        /**
         * Initialize FreeFormer
         * @param {Object} options - Configuration options
         */
        init: function (options) {
            this.config = { ...this.config, ...options };

            if (this.config.debug) {
                console.log('FreeFormer initialized with config:', this.config);
            }

            // Load Turnstile script if not already loaded
            if (!window.turnstile && this.config.turnstileSiteKey) {
                this.loadTurnstile();
            }

            // Auto-initialize forms if enabled
            if (this.config.autoInit) {
                this.autoInitForms();
            }
        },

        /**
         * Load Turnstile script dynamically
         */
        loadTurnstile: function () {
            if (document.querySelector('script[src*="turnstile"]')) {
                return; // Already loaded
            }

            const script = document.createElement('script');
            script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
            script.async = true;
            script.defer = true;
            document.head.appendChild(script);

            if (this.config.debug) {
                console.log('Turnstile script loaded');
            }
        },

        /**
         * Auto-initialize forms with data-freeformer attribute
         */
        autoInitForms: function () {
            const forms = document.querySelectorAll('[data-freeformer]');
            forms.forEach(form => {
                const formId = form.dataset.freeformer || form.id || 'default-form';
                this.attachForm(form, formId);
            });

            if (this.config.debug) {
                console.log(`Auto-initialized ${forms.length} form(s)`);
            }
        },

        /**
         * Attach FreeFormer to a specific form
         * @param {HTMLFormElement|string} form - Form element or selector
         * @param {string} formId - Unique form identifier
         */
        attachForm: function (form, formId) {
            const formElement = typeof form === 'string' ? document.querySelector(form) : form;

            if (!formElement) {
                console.error('FreeFormer: Form not found');
                return;
            }

            // Add Turnstile widget if not present
            if (this.config.turnstileSiteKey && !formElement.querySelector('.cf-turnstile')) {
                this.addTurnstileWidget(formElement);
            }

            // Attach submit handler
            formElement.addEventListener('submit', (e) => {
                this.handleSubmit(e, formId);
            });

            if (this.config.debug) {
                console.log(`Form attached: ${formId}`);
            }
        },

        /**
         * Add Turnstile widget to form
         * @param {HTMLFormElement} form - Form element
         */
        addTurnstileWidget: function (form) {
            const container = document.createElement('div');
            container.className = 'freeformer-turnstile-container';
            container.style.margin = '20px 0';
            container.style.display = 'flex';
            container.style.justifyContent = 'center';

            const widget = document.createElement('div');
            widget.className = 'cf-turnstile';
            widget.setAttribute('data-sitekey', this.config.turnstileSiteKey);

            container.appendChild(widget);

            // Insert before submit button
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.parentNode.insertBefore(container, submitBtn);
            } else {
                form.appendChild(container);
            }
        },

        /**
         * Handle form submission
         * @param {Event} e - Submit event
         * @param {string} formId - Form identifier
         */
        handleSubmit: async function (e, formId) {
            e.preventDefault();

            const form = e.target;
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.textContent : '';

            // Disable submit button
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Submitting...';
            }

            try {
                // Get form data
                const formData = new FormData(form);
                const data = {};

                for (const [key, value] of formData.entries()) {
                    if (data[key]) {
                        if (Array.isArray(data[key])) {
                            data[key].push(value);
                        } else {
                            data[key] = [data[key], value];
                        }
                    } else {
                        data[key] = value;
                    }
                }

                // Get Turnstile token
                const turnstileToken = this.getTurnstileToken(form);

                if (this.config.turnstileSiteKey && !turnstileToken) {
                    this.showMessage(form, 'Please complete the verification', 'error');
                    return;
                }

                // Resolve siteId: explicit dataset/config -> auto-extract hostname from window.location
                const explicitSiteId = form.dataset.freeformerSite || form.dataset.siteId || this.config.siteId;
                let autoSiteId = '';
                if (typeof window !== 'undefined' && window.location && window.location.hostname) {
                    autoSiteId = window.location.hostname.replace(/^www\./i, '').toLowerCase();
                }
                const siteId = (explicitSiteId || autoSiteId || '').trim();

                if (!siteId) {
                    const errorMsg = 'FreeFormer: Missing required site ID. Add data-freeformer-site="mysite" to your <form> or set siteId in FreeFormer.init().';
                    console.error(errorMsg);
                    this.showMessage(form, 'Configuration error: Missing site ID', 'error');
                    return;
                }

                // Resolve protected fields from dataset or config
                const protectedRaw = form.dataset.freeformerProtectedFields ||
                    form.dataset.protectedFields ||
                    form.dataset.freeformerSensitiveFields ||
                    form.dataset.sensitiveFields || '';
                const protectedFields = protectedRaw
                    ? protectedRaw.split(',').map(s => s.trim()).filter(Boolean)
                    : (Array.isArray(this.config.protectedFields) ? this.config.protectedFields : []);

                // Check if form contains any file inputs with selected files
                let hasFiles = false;
                for (const value of formData.values()) {
                    if (typeof File !== 'undefined' && value instanceof File && value.name && value.size > 0) {
                        hasFiles = true;
                        break;
                    }
                }

                // Submit to FreeFormer
                let response;
                if (hasFiles) {
                    const submissionBody = new FormData();
                    submissionBody.append('formId', formId);
                    submissionBody.append('siteId', siteId);
                    submissionBody.append('turnstileToken', turnstileToken);
                    for (const [key, value] of formData.entries()) {
                        submissionBody.append(key, value);
                    }
                    const headers = {};
                    if (protectedFields.length > 0) {
                        headers['X-FreeFormer-Protected-Fields'] = protectedFields.join(',');
                    }
                    response = await fetch(`${this.config.workerUrl}/submit`, {
                        method: 'POST',
                        headers,
                        body: submissionBody,
                    });
                } else {
                    response = await fetch(`${this.config.workerUrl}/submit`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(protectedFields.length > 0 ? { 'X-FreeFormer-Protected-Fields': protectedFields.join(',') } : {}),
                        },
                        body: JSON.stringify({
                            formId: formId,
                            siteId: siteId,
                            turnstileToken: turnstileToken,
                            data: data,
                            options: {
                                protectedFields: protectedFields.length > 0 ? protectedFields : undefined,
                            },
                        }),
                    });
                }

                const result = await response.json();

                if (result.success) {
                    this.showMessage(form, 'Form submitted successfully!', 'success');
                    form.reset();
                    this.resetTurnstile(form);

                    // Trigger custom event
                    form.dispatchEvent(new CustomEvent('freeformer:success', {
                        detail: { submissionId: result.submissionId, formId: formId }
                    }));
                } else {
                    let errorMsg = result.error || 'Submission failed';
                    if (result.details && result.details.length > 0) {
                        errorMsg += ': ' + result.details.join(', ');
                    }
                    this.showMessage(form, errorMsg, 'error');
                    this.resetTurnstile(form);

                    // Trigger custom event
                    form.dispatchEvent(new CustomEvent('freeformer:error', {
                        detail: { error: errorMsg, formId: formId }
                    }));
                }
            } catch (error) {
                console.error('FreeFormer submission error:', error);
                this.showMessage(form, 'Network error. Please try again.', 'error');
                this.resetTurnstile(form);

                // Trigger custom event
                form.dispatchEvent(new CustomEvent('freeformer:error', {
                    detail: { error: error.message, formId: formId }
                }));
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalBtnText;
                }
            }
        },

        /**
         * Get Turnstile token from form
         * @param {HTMLFormElement} form - Form element
         * @returns {string|null} Turnstile token
         */
        getTurnstileToken: function (form) {
            if (!window.turnstile) return null;

            const widget = form.querySelector('.cf-turnstile');
            if (!widget) return null;

            const widgetId = widget.dataset.widgetId;
            if (widgetId !== undefined) {
                return turnstile.getResponse(widgetId);
            }

            return turnstile.getResponse();
        },

        /**
         * Reset Turnstile widget
         * @param {HTMLFormElement} form - Form element
         */
        resetTurnstile: function (form) {
            if (!window.turnstile) return;

            const widget = form.querySelector('.cf-turnstile');
            if (!widget) return;

            const widgetId = widget.dataset.widgetId;
            if (widgetId !== undefined) {
                turnstile.reset(widgetId);
            } else {
                turnstile.reset();
            }
        },

        /**
         * Show message to user
         * @param {HTMLFormElement} form - Form element
         * @param {string} message - Message text
         * @param {string} type - Message type (success/error)
         */
        showMessage: function (form, message, type) {
            // Look for existing message container
            let messageDiv = form.querySelector('.freeformer-message');

            if (!messageDiv) {
                // Create message container
                messageDiv = document.createElement('div');
                messageDiv.className = 'freeformer-message';
                form.insertBefore(messageDiv, form.firstChild);
            }

            // Style the message
            messageDiv.textContent = message;
            messageDiv.className = `freeformer-message freeformer-message-${type}`;
            messageDiv.style.padding = '12px 16px';
            messageDiv.style.borderRadius = '8px';
            messageDiv.style.marginBottom = '16px';
            messageDiv.style.fontSize = '14px';
            messageDiv.style.display = 'block';

            if (type === 'success') {
                messageDiv.style.background = '#d4edda';
                messageDiv.style.color = '#155724';
                messageDiv.style.border = '1px solid #c3e6cb';
            } else if (type === 'error') {
                messageDiv.style.background = '#f8d7da';
                messageDiv.style.color = '#721c24';
                messageDiv.style.border = '1px solid #f5c6cb';
            }

            // Auto-hide after 5 seconds
            setTimeout(() => {
                messageDiv.style.display = 'none';
            }, 5000);
        }
    };

    // Expose to window
    window.FreeFormer = FreeFormer;

})(window);
