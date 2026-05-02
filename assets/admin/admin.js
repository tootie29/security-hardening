/**
 * RichardMedina Security Hardening — admin scripts.
 * Vanilla JS, no jQuery dependency.
 */
(function () {
	'use strict';

	function bindCopyButtons() {
		document.querySelectorAll('.rm-sh-copy').forEach(function (btn) {
			btn.addEventListener('click', async function (e) {
				e.preventDefault();
				const targetSel = btn.getAttribute('data-target');
				if (!targetSel) {
					return;
				}
				const target = document.querySelector(targetSel);
				if (!target) {
					return;
				}
				const text = target.value !== undefined ? target.value : target.innerText;
				try {
					if (navigator.clipboard && navigator.clipboard.writeText) {
						await navigator.clipboard.writeText(text);
					} else {
						target.select();
						document.execCommand('copy');
					}
				} catch (err) {
					return;
				}
				const original = btn.textContent;
				btn.textContent = 'Copied';
				btn.classList.add('is-copied');
				window.setTimeout(function () {
					btn.textContent = original;
					btn.classList.remove('is-copied');
				}, 2000);
			});
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', bindCopyButtons);
	} else {
		bindCopyButtons();
	}
})();
