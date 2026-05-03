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

	/**
	 * Sticky save bar — shows when the settings form has unsaved changes.
	 * Snapshots initial form state and compares on every input/change.
	 */
	function bindSaveBar() {
		const form    = document.getElementById('rm-sh-form');
		const savebar = document.querySelector('[data-rm-sh-savebar]');
		if (!form || !savebar) {
			return;
		}

		const snapshot = function () {
			const data = new FormData(form);
			const out  = [];
			for (const pair of data.entries()) {
				out.push(pair[0] + '=' + pair[1]);
			}
			out.sort();
			return out.join('&');
		};

		let initial = snapshot();

		const update = function () {
			const dirty = snapshot() !== initial;
			savebar.hidden = !dirty;
		};

		form.addEventListener('input',  update);
		form.addEventListener('change', update);

		// Discard buttons reset the form and re-snapshot.
		document.querySelectorAll('[data-rm-sh-discard]').forEach(function (btn) {
			btn.addEventListener('click', function (e) {
				e.preventDefault();
				form.reset();
				// reset() doesn't re-fire input event for radios/selects in some cases — give it a tick
				window.setTimeout(function () {
					initial = snapshot();
					update();
				}, 0);
			});
		});

		// Clicking Save re-snapshots after the round-trip (handled via page reload anyway).
		// Warn on navigate-away if dirty.
		window.addEventListener('beforeunload', function (e) {
			if (snapshot() !== initial) {
				e.preventDefault();
				e.returnValue = '';
			}
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', function () {
			bindCopyButtons();
			bindSaveBar();
		});
	} else {
		bindCopyButtons();
		bindSaveBar();
	}
})();
