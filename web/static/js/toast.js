// Тост-уведомления в правом нижнем углу — общий механизм для всех страниц.
// Использование: window.showToast({ icon: '🏆', title: 'Достижение получено', body: 'Первая эмоция' })
// С кнопками действия (не гаснет по клику мимо, только по кнопке/таймауту):
//   window.showToast({ icon: '🎬', title: '...', body: '...',
//     actions: [{ label: 'Принять', onClick: fn }, { label: 'Отклонить', onClick: fn }] })
(function () {
    function ensureContainer() {
        var el = document.getElementById('toast-container');
        if (!el) {
            el = document.createElement('div');
            el.id = 'toast-container';
            document.body.appendChild(el);
        }
        return el;
    }

    window.showToast = function (opts) {
        var container = ensureContainer();
        var toast = document.createElement('div');
        toast.className = 'toast';
        var actions = opts.actions || [];
        var actionsHtml = actions.length
            ? '<div class="toast-actions">' + actions.map(function (a, i) {
                return '<button type="button" class="btn btn-sm toast-action-btn" data-action-index="' + i + '">' + a.label + '</button>';
            }).join('') + '</div>'
            : '';
        toast.innerHTML =
            (opts.icon ? '<span class="toast-icon">' + opts.icon + '</span>' : '') +
            '<span class="toast-content"><div class="toast-title"></div><div class="toast-body"></div>' + actionsHtml + '</span>';
        toast.querySelector('.toast-title').textContent = opts.title || '';
        toast.querySelector('.toast-body').textContent = opts.body || '';

        var dismissed = false;
        function dismiss() {
            if (dismissed) return;
            dismissed = true;
            toast.classList.remove('in-view');
            setTimeout(function () { toast.remove(); }, 350);
        }
        toast.querySelectorAll('.toast-action-btn').forEach(function (btn, i) {
            btn.addEventListener('click', function () {
                actions[i].onClick();
                dismiss();
            });
        });

        container.appendChild(toast);
        requestAnimationFrame(function () { toast.classList.add('in-view'); });
        setTimeout(dismiss, opts.duration || 5000);
    };
})();
